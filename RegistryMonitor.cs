using LogSentry.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace LogSentry;

/// <summary>Registry Monitor. Subscribes to Microsoft-Windows-Kernel-Registry, monitors Run/RunOnce writes, alerts on non-trusted writers.</summary>
public sealed class RegistryMonitor
{
    /// <summary>Microsoft-Windows-Kernel-Registry provider GUID.</summary>
    public static readonly Guid KernelRegistryProviderGuid = new("70EB4F03-C1DE-4F73-A051-33D13D5413BD");

    private static readonly HashSet<string> TrustedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "services.exe", "winlogon.exe", "explorer.exe",
        "msiexec.exe", "setup.exe", "installer.exe", "OneDrive.exe",
        "SecurityHealthService.exe", "MsMpEng.exe", "NisSrv.exe",
        "SearchHost.exe", "SystemSettings.exe", "ApplicationFrameHost.exe",
        "RuntimeBroker.exe", "dllhost.exe", "conhost.exe", "fontdrvhost.exe",
        "sihost.exe", "taskhostw.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
        "TrustedInstaller.exe", "TiWorker.exe"
    };

    private static readonly string[] PersistenceKeySuffixes =
    {
        "\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    private readonly Func<int, string?> _resolveProcessName;

    public event Action<RegistryWriteEvent>? OnRegistryWrite;

    public RegistryMonitor(Func<int, string?> resolveProcessName)
    {
        _resolveProcessName = resolveProcessName;
    }

    public void Subscribe(TraceEventSession session, TraceEventSource source)
    {
        source.Dynamic.All += evt =>
        {
            try
            {
                if (evt.ProviderGuid != KernelRegistryProviderGuid)
                    return;

                string? keyPath = GetPayloadString(evt, "KeyName")
                    ?? GetPayloadString(evt, "RelativeName")
                    ?? GetPayloadString(evt, "ObjectName");

                if (string.IsNullOrWhiteSpace(keyPath))
                    return;

                string normalizedKey = keyPath.Replace('/', '\\');
                bool isPersistence = IsPersistenceKey(normalizedKey);

                int processId = evt.ProcessID;
                string processName = _resolveProcessName(processId) ?? $"PID:{processId}";
                bool isNonTrusted = !TrustedProcessNames.Contains(processName);

                string? valueName = GetPayloadString(evt, "ValueName") ?? GetPayloadString(evt, "Value");
                string? valueData = GetPayloadString(evt, "ValueData") ?? GetPayloadString(evt, "Data");

                // Do not alert on pointless empty writes or noise without values
                if (isPersistence && isNonTrusted && string.IsNullOrWhiteSpace(valueData) && string.IsNullOrWhiteSpace(valueName))
                    return;

                var regEvent = new RegistryWriteEvent
                {
                    Module = "RegistryMonitor",
                    EventType = "RegistrySetValue",
                    ProcessId = processId,
                    ProcessName = processName,
                    KeyPath = normalizedKey,
                    ValueName = valueName,
                    ValueData = valueData,
                    IsPersistenceKey = isPersistence,
                    IsNonTrustedWriter = isNonTrusted
                };

                OnRegistryWrite?.Invoke(regEvent);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Registry Monitor] Error processing registry event: {ex.Message}");
            }
        };
    }

    private static bool IsPersistenceKey(string keyPath)
    {
        foreach (var suffix in PersistenceKeySuffixes)
        {
            if (keyPath.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return true;
            if (keyPath.Contains("CurrentVersion\\Run", StringComparison.OrdinalIgnoreCase) &&
                (keyPath.Contains("Microsoft\\Windows", StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        return false;
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
}
