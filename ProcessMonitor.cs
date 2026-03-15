using System.Collections.Concurrent;
using LogSentry.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace LogSentry;

/// <summary>Process Monitor. Subscribes to Microsoft-Windows-Kernel-Process, captures process start, detects parent-child and temp execution anomalies.</summary>
public sealed class ProcessMonitor
{
    private static readonly string[] SuspiciousParents = { "notepad.exe", "calculator.exe", "calc.exe" };
    private static readonly string[] SuspiciousChildren = { "cmd.exe", "powershell.exe" };
    private static readonly StringComparison NameComparison = StringComparison.OrdinalIgnoreCase;

    private readonly ConcurrentDictionary<int, string> _pidToName = new();
    private readonly string _tempPathPrefix;

    public event Action<ProcessStartEvent>? OnProcessEvent;

    public ProcessMonitor()
    {
        var tempPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Temp");
        _tempPathPrefix = tempPath.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
    }

    public void Subscribe(TraceEventSession session, TraceEventSource source)
    {
        source.Kernel.ProcessStart += evt =>
        {
            try
            {
                string processName = evt.ProcessName ?? string.Empty;
                int pid = evt.ProcessID;
                int parentId = evt.ParentID;

                _pidToName[pid] = processName;
                string? parentName = parentId > 0 ? _pidToName.GetValueOrDefault(parentId) : null;

                string? imagePath = GetPayloadString(evt, "ImageFileName");
                if (string.IsNullOrEmpty(imagePath) && GetPayloadString(evt, "CommandLine") is { } cmd)
                    imagePath = GetImageFromCommandLine(cmd);

                bool parentChildAnomaly = IsParentChildAnomaly(processName, parentName);
                bool tempAnomaly = IsTempExecutionAnomaly(imagePath);

                var processEvent = new ProcessStartEvent
                {
                    Module = "ProcessMonitor",
                    EventType = "ProcessStart",
                    ProcessId = pid,
                    ProcessName = processName,
                    ParentProcessId = parentId,
                    ParentProcessName = parentName,
                    ImagePath = imagePath,
                    CommandLine = GetPayloadString(evt, "CommandLine"),
                    IsParentChildAnomaly = parentChildAnomaly,
                    IsTempExecutionAnomaly = tempAnomaly
                };

                OnProcessEvent?.Invoke(processEvent);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Process Monitor] Error processing ProcessStart: {ex.Message}");
            }
        };

        source.Kernel.ProcessStop += evt =>
        {
            _pidToName.TryRemove(evt.ProcessID, out _);
        };
    }

    private static bool IsParentChildAnomaly(string childName, string? parentName)
    {
        if (string.IsNullOrEmpty(parentName)) return false;
        bool childSuspicious = SuspiciousChildren.Any(c => c.Equals(childName, NameComparison));
        bool parentSuspicious = SuspiciousParents.Any(p => p.Equals(parentName, NameComparison));
        return childSuspicious && parentSuspicious;
    }

    private bool IsTempExecutionAnomaly(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;
        try
        {
            var normalized = Path.GetFullPath(imagePath.Trim('"'));
            return normalized.StartsWith(_tempPathPrefix, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return imagePath.Contains("AppData\\Local\\Temp", NameComparison) ||
                   imagePath.Contains("AppData/Local/Temp", NameComparison);
        }
    }

    private static string? GetPayloadString(TraceEvent evt, string name)
    {
        try
        {
            var v = evt.PayloadByName(name);
            return v?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static string? GetImageFromCommandLine(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var first = commandLine.Trim().Split(new[] { ' ', '\t' }, 2, StringSplitOptions.None)[0].Trim('"');
        return first;
    }

    public string? GetProcessName(int processId) => _pidToName.GetValueOrDefault(processId);
}
