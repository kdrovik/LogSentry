namespace LogSentry.Models;

/// <summary>Base type for all security telemetry events.</summary>
public abstract record SecurityEventBase
{
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
    public string Module { get; init; } = string.Empty;
    public string EventType { get; init; } = string.Empty;
    public string? CorrelationId { get; init; }
}

/// <summary>Process start event from Process Monitor.</summary>
public record ProcessStartEvent : SecurityEventBase
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public int ParentProcessId { get; init; }
    public string? ParentProcessName { get; init; }
    public string? ImagePath { get; init; }
    public string? CommandLine { get; init; }
    public bool IsParentChildAnomaly { get; init; }
    public bool IsTempExecutionAnomaly { get; init; }
    public bool IsSuspicious => IsParentChildAnomaly || IsTempExecutionAnomaly;
}

/// <summary>DNS query event from DNS Monitor.</summary>
public record DnsQueryEvent : SecurityEventBase
{
    public int ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string QueryName { get; init; } = string.Empty;
    public bool IsDgaSuspicious { get; init; }
}

/// <summary>Registry write event from Registry Monitor.</summary>
public record RegistryWriteEvent : SecurityEventBase
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string KeyPath { get; init; } = string.Empty;
    public string? ValueName { get; init; }
    public string? ValueData { get; init; }
    public bool IsPersistenceKey { get; init; }
    public bool IsNonTrustedWriter { get; init; }
}

/// <summary>Correlated incident from Event Correlator.</summary>
public record IncidentReport : SecurityEventBase
{
    public string Priority { get; init; } = "Medium"; // Low, Medium, High, Critical
    public string Summary { get; init; } = string.Empty;
    public List<string> ContributingEventIds { get; init; } = new();
    public ProcessStartEvent? ProcessEvent { get; init; }
    public DnsQueryEvent? DnsEvent { get; init; }
    public RegistryWriteEvent? RegistryEvent { get; init; }
}
