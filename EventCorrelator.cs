using System.Collections.Concurrent;
using System.Text.Json;
using LogSentry.Models;

namespace LogSentry;

/// <summary>Event Correlator. Correlates events from process, DNS, and registry monitors; escalates combined sequences to High Priority; exports JSON/SIEM-ready logs.</summary>
public sealed class EventCorrelator
{
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private readonly ConcurrentDictionary<int, List<CorrelationEntry>> _recentByPid = new();
    private readonly string _outputDirectory;
    /// <summary>Directory where JSONL log files are written.</summary>
    public string OutputDirectory => _outputDirectory;
    private readonly object _fileLock = new();
    private readonly bool _consoleAlerts;

    public event Action<IncidentReport>? OnIncident;

    public EventCorrelator(string? outputDirectory = null, bool consoleAlerts = true)
    {
        _outputDirectory = outputDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LogSentry");
        _consoleAlerts = consoleAlerts;
        try
        {
            Directory.CreateDirectory(_outputDirectory);
        }
        catch { /* ignore */ }
    }

    public void Attach(ProcessMonitor processMonitor, DnsMonitor dnsMonitor, RegistryMonitor registryMonitor)
    {
        processMonitor.OnProcessEvent += OnProcessEvent;
        dnsMonitor.OnDnsQuery += OnDnsQuery;
        registryMonitor.OnRegistryWrite += OnRegistryWrite;
    }

    private void OnProcessEvent(ProcessStartEvent evt)
    {
        AddEntry(evt.ProcessId, "Process", evt, evt.IsSuspicious ? "SuspiciousProcess" : null);
        ExportEvent(evt);
    }

    private void OnDnsQuery(DnsQueryEvent evt)
    {
        AddEntry(evt.ProcessId, "Dns", evt, evt.IsDgaSuspicious ? "DgaQuery" : null);
        ExportEvent(evt);
    }

    private void OnRegistryWrite(RegistryWriteEvent evt)
    {
        AddEntry(evt.ProcessId, "Registry", evt, (evt.IsPersistenceKey && evt.IsNonTrustedWriter) ? "PersistenceWrite" : null);
        ExportEvent(evt);
    }

    private void AddEntry(int processId, string kind, SecurityEventBase evt, string? flag)
    {
        var list = _recentByPid.GetOrAdd(processId, _ => new List<CorrelationEntry>());
        lock (list)
        {
            list.Add(new CorrelationEntry(evt.TimestampUtc, kind, evt, flag));
            Prune(list, evt.TimestampUtc - CorrelationWindow);
            if (flag != null)
                TryCorrelate(processId, list);
        }
    }

    private void Prune(List<CorrelationEntry> list, DateTime cutoff)
    {
        for (int i = list.Count - 1; i >= 0; i--)
        {
            if (list[i].At < cutoff)
                list.RemoveAt(i);
        }
    }

    private void TryCorrelate(int processId, List<CorrelationEntry> list)
    {
        bool hasSuspiciousProcess = list.Any(e => e.Flag == "SuspiciousProcess");
        bool hasDga = list.Any(e => e.Flag == "DgaQuery");
        bool hasPersistence = list.Any(e => e.Flag == "PersistenceWrite");

        if (hasSuspiciousProcess && hasDga && hasPersistence)
        {
            var processEvt = list.LastOrDefault(e => e.Flag == "SuspiciousProcess")?.Event as ProcessStartEvent;
            var dnsEvt = list.LastOrDefault(e => e.Flag == "DgaQuery")?.Event as DnsQueryEvent;
            var regEvt = list.LastOrDefault(e => e.Flag == "PersistenceWrite")?.Event as RegistryWriteEvent;

            var incident = new IncidentReport
            {
                Module = "Correlator",
                EventType = "CorrelatedIncident",
                Priority = "High",
                Summary = $"Correlated threat: anomalous process (PID {processId}) performed DGA-like DNS query and wrote to persistence key.",
                ContributingEventIds = new List<string>
                {
                    processEvt?.EventType ?? "ProcessStart",
                    dnsEvt?.EventType ?? "DnsQuery",
                    regEvt?.EventType ?? "RegistrySetValue"
                },
                ProcessEvent = processEvt,
                DnsEvent = dnsEvt,
                RegistryEvent = regEvt
            };

            ExportEvent(incident);
            OnIncident?.Invoke(incident);

            if (_consoleAlerts)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[Correlator] HIGH PRIORITY: {incident.Summary}");
                Console.ResetColor();
            }
        }
    }

    private void ExportEvent(SecurityEventBase evt)
    {
        try
        {
            string json = JsonSerializer.Serialize(evt, evt.GetType(), JsonOptions);
            string fileName = $"LogSentry_{evt.Module}_{evt.EventType}_{DateTime.UtcNow:yyyyMMdd}.jsonl";
            string path = Path.Combine(_outputDirectory, fileName);
            lock (_fileLock)
            {
                File.AppendAllText(path, json + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Correlator] Export error: {ex.Message}");
        }
    }

    private record CorrelationEntry(DateTime At, string Kind, SecurityEventBase Event, string? Flag);
}
