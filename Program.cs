using System.Diagnostics;
using LogSentry.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace LogSentry;

static class Program
{
    static void Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            Console.WriteLine();
            Console.WriteLine("[CRASH] " + ((Exception)e.ExceptionObject).ToString());
            WaitBeforeExit();
        };

        Console.WriteLine("=== LogSentry ETW Monitor ===");
        Console.WriteLine("Modules: Process | DNS | Registry | Correlator");
        Console.WriteLine();
        Flush();

        bool elevated = TraceEventSession.IsElevated() ?? false;
        if (!elevated)
        {
            Console.WriteLine("Warning: Not running as Administrator. Some ETW providers may fail.");
            Console.WriteLine();
            Flush();
        }

        string sessionName = "LogSentry_" + Guid.NewGuid().ToString("N")[..8];
        string? outputDir = args.Length > 0 ? args[0].Trim() : null;

        var processMonitor = new ProcessMonitor();
        string? ResolveProcess(int pid) => processMonitor.GetProcessName(pid) ?? TryGetProcessNameByPid(pid);

        var dnsMonitor = new DnsMonitor(ResolveProcess);
        var registryMonitor = new RegistryMonitor(ResolveProcess);
        var eventCorrelator = new EventCorrelator(outputDir, consoleAlerts: true);

        eventCorrelator.Attach(processMonitor, dnsMonitor, registryMonitor);

        processMonitor.OnProcessEvent += evt =>
        {
            if (evt.IsSuspicious)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[Process Monitor] Suspicious process: PID={evt.ProcessId} {evt.ProcessName} (Parent: {evt.ParentProcessName}) " +
                    $"| ParentChildAnomaly={evt.IsParentChildAnomaly} TempAnomaly={evt.IsTempExecutionAnomaly}");
                Console.ResetColor();
            }
        };

        dnsMonitor.OnDnsQuery += evt =>
        {
            if (evt.IsDgaSuspicious)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine($"[DNS Monitor] DGA-suspicious DNS: PID={evt.ProcessId} Query={evt.QueryName}");
                Console.ResetColor();
            }
        };

        registryMonitor.OnRegistryWrite += evt =>
        {
            if (evt.IsPersistenceKey && evt.IsNonTrustedWriter)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"[Registry Monitor] Persistence write: PID={evt.ProcessId} {evt.ProcessName} Key={evt.KeyPath} Value={evt.ValueData}");
                Console.ResetColor();
            }
        };

        try
        {
            Console.WriteLine("Creating ETW session...");
            Flush();
            using var session = new TraceEventSession(sessionName);

            Console.WriteLine("Enabling Kernel (Process) provider...");
            Flush();
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

            Console.WriteLine("Enabling DNS-Client provider...");
            Flush();
            try
            {
                session.EnableProvider(DnsMonitor.DnsClientProviderGuid, TraceEventLevel.Verbose, 0xFFFFFFFF);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DNS Monitor] Provider skipped: {ex.Message}");
                Flush();
            }

            Console.WriteLine("Enabling Kernel-Registry provider...");
            Flush();
            try
            {
                session.EnableProvider(RegistryMonitor.KernelRegistryProviderGuid, TraceEventLevel.Informational, 0xFFFFFFFF);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Registry Monitor] Provider skipped: {ex.Message}");
                Flush();
            }

            Console.WriteLine("Connecting event source...");
            Flush();
            using var source = new ETWTraceEventSource(sessionName, TraceEventSourceType.Session);

            Console.WriteLine("Subscribing Process Monitor...");
            Flush();
            processMonitor.Subscribe(session, source);

            Console.WriteLine("Subscribing DNS Monitor...");
            Flush();
            dnsMonitor.Subscribe(session, source);

            Console.WriteLine("Subscribing Registry Monitor...");
            Flush();
            registryMonitor.Subscribe(session, source);

            Console.WriteLine($"Session: {sessionName}. Listening for ETW events (Ctrl+C to stop).");
            Console.WriteLine($"Logs: {eventCorrelator.OutputDirectory}");
            Console.WriteLine();
            Flush();

            source.Process();
        }
        catch (Exception ex)
        {
            Console.WriteLine();
            Console.WriteLine("Fatal: " + ex.ToString());
            Flush();
            WaitBeforeExit();
            Environment.Exit(1);
        }
    }

    /// <summary>Resolves process name by PID when it's not in the ProcessMonitor cache (e.g. processes that were already running).</summary>
    static string? TryGetProcessNameByPid(int pid)
    {
        if (pid <= 0) return null;
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName + ".exe";
        }
        catch
        {
            return null;
        }
    }

    static void Flush()
    {
        try { Console.Out.Flush(); } catch { }
    }

    static void WaitBeforeExit()
    {
        Console.WriteLine();
        Console.WriteLine("Press Enter to exit.");
        try { Console.ReadLine(); } catch { }
    }
}
