using System.Text.RegularExpressions;
using LogSentry.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace LogSentry;

/// <summary>DNS Monitor. Subscribes to Microsoft-Windows-DNS-Client, captures DNS queries, detects DGA-like domains.</summary>
public sealed class DnsMonitor
{
    /// <summary>Microsoft-Windows-DNS-Client provider GUID.</summary>
    public static readonly Guid DnsClientProviderGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    private static readonly Regex DgaPattern = new(
        @"^([a-z]{2,6}[0-9]{4,}|[0-9]{4,}[a-z]{2,6})\.(xyz|top|tk|ml|ga|cf|gq|cc|ru|cn|work|click|link|online|site|tech|pw|info|biz)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex RandomSubdomain = new(
        @"^[a-z0-9]{10,32}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly Func<int, string?> _resolveProcessName;

    public event Action<DnsQueryEvent>? OnDnsQuery;

    public DnsMonitor(Func<int, string?> resolveProcessName)
    {
        _resolveProcessName = resolveProcessName;
    }

    public void Subscribe(TraceEventSession session, TraceEventSource source)
    {
        source.Dynamic.All += evt =>
        {
            try
            {
                if (evt.ProviderGuid != DnsClientProviderGuid)
                    return;

                string? queryName = GetPayloadString(evt, "QueryName")
                    ?? GetPayloadString(evt, "Query")
                    ?? GetPayloadString(evt, "QueryNameLength"); // fallback: some use different names

                if (string.IsNullOrWhiteSpace(queryName))
                {
                    for (int i = 0; i < evt.PayloadNames?.Length; i++)
                    {
                        if (evt.PayloadNames[i]?.Contains("Query", StringComparison.OrdinalIgnoreCase) == true)
                        {
                            queryName = evt.PayloadValue(i)?.ToString();
                            break;
                        }
                    }
                }

                if (string.IsNullOrWhiteSpace(queryName))
                    return;

                queryName = queryName.Trim();
                int processId = evt.ProcessID;
                string? processName = _resolveProcessName(processId);
                bool isDga = IsDgaSuspicious(queryName);

                var dnsEvent = new DnsQueryEvent
                {
                    Module = "DNS",
                    EventType = "DnsQuery",
                    ProcessId = processId,
                    ProcessName = processName,
                    QueryName = queryName,
                    IsDgaSuspicious = isDga
                };

                OnDnsQuery?.Invoke(dnsEvent);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DNS] Error processing DNS event: {ex.Message}");
            }
        };
    }

    /// <summary>Heuristic: random-looking label + suspicious TLD (e.g. asdfg12345.xyz).</summary>
    private static bool IsDgaSuspicious(string queryName)
    {
        if (string.IsNullOrEmpty(queryName) || queryName.Length > 253)
            return false;

        int dot = queryName.IndexOf('.');
        string label = dot >= 0 ? queryName.AsSpan(0, dot).ToString() : queryName;
        string tld = dot >= 0 && dot < queryName.Length - 1 ? queryName[(dot + 1)..].ToLowerInvariant() : "";

        if (DgaPattern.IsMatch(queryName))
            return true;

        if (label.Length >= 10 && RandomSubdomain.IsMatch(label))
        {
            var suspiciousTlds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "xyz", "top", "tk", "ml", "ga", "cf", "gq", "cc", "work", "click", "link", "online", "site", "pw" };
            if (suspiciousTlds.Contains(tld))
                return true;
        }

        int digitCount = label.Count(char.IsDigit);
        int letterCount = label.Count(char.IsLetter);
        if (label.Length >= 8 && digitCount >= 3 && letterCount >= 2 && (digitCount + letterCount) >= label.Length * 9 / 10)
        {
            if (tld.Length >= 2 && tld.Length <= 4)
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
