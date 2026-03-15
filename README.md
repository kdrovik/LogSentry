# LogSentry

**LogSentry** is a **Windows-only** .NET 8 (C#) console application that acts as a **real-time security telemetry sensor**, using the **Microsoft.Diagnostics.Tracing.TraceEvent** library for **Event Tracing for Windows (ETW)**. It captures critical system events (process creation, DNS queries, registry writes) before potential attacker deletion and correlates them to detect suspicious sequences.

| | |
|---|---|
| **Project name** | **LogSentry** — *sentry* as in guarding and logging security-relevant events |
| **Runtime** | .NET 8, Windows (ETW) |
| **Repo / binary** | Folder and assembly name: `LogSentry` |

---

## Table of Contents

- [What Does LogSentry Do?](#what-does-logsentry-do)
- [How LogSentry Works](#how-logsentry-works)
- [Architecture & Modules](#architecture--modules)
- [Detection Logic in Detail](#detection-logic-in-detail)
- [Requirements](#requirements)
- [Build & Run](#build--run)
- [Quick Start & Example Workflow](#quick-start--example-workflow)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Output Files](#output-files)
- [Limitations & False Positives](#limitations--false-positives)
- [Troubleshooting](#troubleshooting)
- [Glossary](#glossary)
- [FAQ](#faq)
- [Security & Legal](#security--legal)
- [Project Structure](#project-structure)
- [References](#references)

---

## What Does LogSentry Do?

LogSentry subscribes to **ETW providers** at the OS level to observe:

1. **Process creation** (Microsoft-Windows-Kernel-Process) — to spot anomalous parent-child relationships and execution from temp folders.
2. **DNS queries** (Microsoft-Windows-DNS-Client) — to spot domain names that look like **DGA** (Domain Generation Algorithm), often used by botnets/ransomware C2.
3. **Registry writes** (Microsoft-Windows-Kernel-Registry) — to spot **persistence** via Run/RunOnce keys by non-trusted processes.

An **Event Correlator** then combines these signals: if an **anomalous process** performs a **DGA-like DNS query** and **writes to a persistence key**, it raises a **High Priority Incident Report**. All events and reports are exported in **JSONL** (SIEM-friendly, machine-readable).

---

## How LogSentry Works

High-level flow:

1. **Create a real-time ETW session**  
   A `TraceEventSession` is created; no log file is required — events are consumed in real time.

2. **Enable providers**
   - **Kernel-Process** — process start/stop.
   - **Microsoft-Windows-DNS-Client** (by GUID) — DNS query/response events.
   - **Microsoft-Windows-Kernel-Registry** (by GUID) — registry operations (e.g. set value).

3. **Subscribe parsers and callbacks**
   - **Process Monitor** subscribes to `Kernel.ProcessStart` / `ProcessStop`, keeps a PID → process name cache, and evaluates parent-child and temp-path rules.
   - **DNS Monitor** subscribes to `Dynamic.All` and filters by DNS-Client provider GUID, then extracts query name and runs DGA heuristics.
   - **Registry Monitor** subscribes to `Dynamic.All` and filters by Kernel-Registry provider GUID, then checks key path (Run/RunOnce) and process trust.

4. **Event Correlator**
   - Receives all events from the three modules.
   - Appends every event to **JSONL** files under a configurable output directory.
   - Keeps a **per-PID, time-windowed** buffer of recent events; if the same process has **suspicious process** + **DGA DNS** + **persistence write** within the window, it emits a **High Priority Incident Report** (and optionally prints to console).

5. **Run until stopped**  
   `source.Process()` blocks until the session is stopped (e.g. Ctrl+C).

---

## Architecture & Modules

| Module | Purpose | ETW provider / API | Main logic |
|--------|--------|--------------------|------------|
| **1 – Process Monitor** | Capture process start; detect parent-child and temp execution anomalies | `Microsoft-Windows-Kernel-Process` (kernel provider, `Keywords.Process`) | Parent-child: cmd/powershell child of notepad/calculator → alert. Temp: image path under `%LocalAppData%\Temp` → suspicious. |
| **2 – DNS Monitor** | Capture DNS queries; flag DGA-like domains | `Microsoft-Windows-DNS-Client` (GUID) | Heuristics: random-looking label + suspicious TLD (e.g. xyz, top, tk); mix of digits/letters in label. |
| **3 – Registry Monitor** | Monitor registry writes; focus on Run/RunOnce | `Microsoft-Windows-Kernel-Registry` (GUID) | Filter keys ending with `\...\CurrentVersion\Run` / `RunOnce`; alert if writer process is not in trusted list; record process name and value/command. |
| **4 – Event Correlator** | Correlate events; export JSONL; escalate combined sequence | N/A (consumes events from 1–3) | Same PID: suspicious process + DGA DNS + persistence write within time window → **High Priority** incident. All events and incidents written to JSONL. |

Data flow:

```
[ETW Session]
       │
       ├──► Process Monitor:  ProcessStart/Stop → PID cache, anomaly flags → ProcessStartEvent
       ├──► DNS Monitor:      DNS-Client events → QueryName, DGA flag → DnsQueryEvent
       └──► Registry Monitor: Kernel-Registry events → KeyPath, Value, trust → RegistryWriteEvent
              │
              ▼
       Event Correlator: event handlers → JSONL export; per-PID buffer → High Priority if triple match
```

---

## Detection Logic in Detail

### Module 1 – Process Monitor

- **Parent-Child Anomaly:**  
  Child process name is `cmd.exe` or `powershell.exe` **and** parent process name is `notepad.exe`, `calculator.exe`, or `calc.exe` → **immediate alert** (suspicious use of benign parents to launch shells).
- **Temporary Execution Anomaly:**  
  Process image path starts with `C:\Users\<UserName>\AppData\Local\Temp` (or equivalent) → marked **suspicious** (common for droppers/scripts).

Process names and parent IDs are resolved from the kernel process events; parent name is taken from a cache updated on every ProcessStart.

### Module 2 – DNS Monitor

- **DGA-style domains:**  
  Patterns such as short letter block + digits (e.g. `asdfg12345.xyz`) or long random-looking labels (e.g. 10–32 alphanumeric chars) with **suspicious TLDs** (e.g. `.xyz`, `.top`, `.tk`, `.pw`, `.work`, `.click`, etc.) → **DGA-suspicious**.  
  Additional heuristic: label length ≥ 8 with a high ratio of digits + letters and a short TLD.

### Module 3 – Registry Monitor

- **Target keys:**  
  Paths containing `Microsoft\Windows\CurrentVersion\Run` or `RunOnce` (including `Wow6432Node` variants).
- **Alert condition:**  
  A **non-trusted** process writes to such a key → alert; **data captured:** process name, key path, value name, and value/command string.
- **Trusted list:**  
  Includes e.g. `svchost.exe`, `explorer.exe`, `msiexec.exe`, `OneDrive.exe`, security/installer-related binaries; others are treated as non-trusted for persistence.

### Module 4 – Event Correlator

- **Correlation window:**  
  Default **5 minutes** per process (per PID).
- **High Priority rule:**  
  For a given PID, if there is at least one **suspicious process** event (Process Monitor), one **DGA-suspicious DNS** event (DNS Monitor), and one **persistence write** (Registry Monitor) in the window → one **High Priority Incident Report** is generated and exported (and optionally printed to console).

---

## Requirements

- **OS:** Windows (e.g. Windows 10/11), 64-bit recommended.
- **Runtime:** .NET 8.0 SDK.
- **Privileges:**  
  **Administrator** is recommended. Kernel and some system ETW providers (e.g. Kernel-Registry) may require elevation; without it, process and DNS may still work but registry monitoring can fail.

---

## Build & Run

```bash
# Clone or open the repo
cd LogSentry

# Restore & build
dotnet restore
dotnet build

# Run (real-time; Ctrl+C to stop)
dotnet run
```

Optional: pass an **output directory** for JSONL logs as the first argument:

```bash
dotnet run -- "C:\LogSentryOutput"
```

Release / self-contained publish:

```bash
dotnet publish -c Release -r win-x64 --self-contained false
# Run: .\LogSentry\bin\Release\net8.0\win-x64\publish\LogSentry.exe
```

---

## Quick Start & Example Workflow

1. **Run as Administrator** (recommended) so Kernel-Registry and kernel process providers work fully.
2. Start LogSentry: `dotnet run` (or the published exe).
3. Generate test signals (optional):
   - **Parent-child anomaly:** Start Notepad, then from Notepad run `cmd.exe` (e.g. via Run or a script) → Process Monitor should flag it.
   - **Temp execution:** Run an executable from `%LocalAppData%\Temp` → Process Monitor should mark it suspicious.
   - **DGA:** Trigger a DNS query to a domain like `test12345abc.xyz` (if your test environment allows) → DNS Monitor may flag it.
   - **Persistence:** Use a non-trusted process to add a value under `HKCU\...\Run` → Registry Monitor should alert.
4. If the **same process** does all three (suspicious process + DGA DNS + persistence write) within the correlation window, Event Correlator prints a **HIGH PRIORITY** message and writes an incident to JSONL.
5. Inspect logs in the output directory (default: `%LocalAppData%\LogSentry` or the path you passed).

---

## Usage

LogSentry is a **single run-and-listen** console app:

| Behavior | Description |
|----------|-------------|
| **Start** | Creates an ETW session, enables Process, DNS-Client, and Kernel-Registry providers, and starts processing. |
| **Console** | Prints alerts for suspicious process, DGA DNS, persistence write, and High Priority correlated incidents (color-coded). |
| **Logs** | Appends all events and incident reports to **JSONL** files under the output directory. |
| **Stop** | Ctrl+C (or closing the console) stops the session and exits. |

Optional first argument: **output directory** for JSONL files.

---

## Sample Output

### Startup

```
=== LogSentry ETW Monitor ===
Modules: Process | DNS | Registry | Correlator

Session: LogSentry_abc12def. Listening for ETW events (Ctrl+C to stop).
Logs: C:\Users\You\AppData\Local\LogSentry
```

### Process Monitor (suspicious process)

```
[Process Monitor] Suspicious process: PID=12345 cmd.exe (Parent: notepad.exe) | ParentChildAnomaly=True TempAnomaly=False
```

### DNS Monitor (DGA-suspicious DNS)

```
[DNS Monitor] DGA-suspicious DNS: PID=12345 Query=asdfg12345.xyz
```

### Registry Monitor (persistence write)

```
[Registry Monitor] Persistence write: PID=12345 myapp.exe Key=...\CurrentVersion\Run Value=C:\malicious\app.exe
```

### Event Correlator (High Priority)

```
[Correlator] HIGH PRIORITY: Correlated threat: anomalous process (PID 12345) performed DGA-like DNS query and wrote to persistence key.
```

---

## Output Files

- **Location:**  
  Default: `%LocalAppData%\LogSentry`. Override with the first command-line argument.
- **Format:**  
  **JSONL** — one JSON object per line (one event or one incident report).
- **Naming:**  
  `LogSentry_<Module>_<EventType>_<YYYYMMDD>.jsonl`  
  Example: `LogSentry_Correlator_CorrelatedIncident_20260314.jsonl`
- **Content:**  
  All `SecurityEventBase`-derived events (process, DNS, registry, incident) in a SIEM-friendly, machine-readable form (camelCase properties, timestamps, process IDs, names, key paths, etc.).

---

## Limitations & False Positives

- **Admin required for full functionality:**  
  Without elevation, Kernel-Registry (and possibly some kernel process details) may not be available; you may see a warning at startup.
- **DGA heuristics:**  
  Pattern-based; legitimate or odd-looking domains can be flagged. Tune the rules or TLD list for your environment.
- **Trusted process list:**  
  Registry Monitor uses a fixed list; legitimate installers or tools not in the list can trigger persistence alerts. Adjust the list as needed.
- **Parent-child rule:**  
  Intentionally strict (notepad/calculator → cmd/powershell). Legitimate automation (e.g. Notepad launching a script) can be flagged.
- **Temp execution:**  
  Many installers and updaters run from Temp; expect some benign positives.
- **Correlation window:**  
  Fixed 5-minute window; fast attacks are covered; very slow or fragmented activity might not correlate.

---

## Troubleshooting

| Issue | What to try |
|--------|-------------|
| **“Could not enable Kernel-Registry provider”** | Run the console as **Administrator**. |
| **No DNS events** | Ensure DNS-Client provider is enabled (GUID correct); check firewall/AV that might block ETW; try a DNS query (e.g. `nslookup test.com`). |
| **No process names / wrong parent** | Process names come from ProcessStart; very short-lived processes may exit before the next event. Parent name is from cache; first few events after start may have no parent name. |
| **Build fails (SDK not found)** | Install [.NET 8 SDK](https://dotnet.microsoft.com/download) and ensure `dotnet` is on PATH. |
| **Session already exists** | Stop any other LogSentry instance or rename the session in code; avoid duplicate session names. |

---

## Glossary

| Term | Meaning |
|------|---------|
| **ETW** | Event Tracing for Windows — OS-level tracing and logging. |
| **Provider** | Source of ETW events (e.g. Microsoft-Windows-Kernel-Process, DNS-Client). |
| **Kernel provider** | Provider that logs kernel-mode events (process, registry, etc.). |
| **DGA** | Domain Generation Algorithm — algorithmically generated domain names, often used by malware for C2. |
| **Run / RunOnce** | Registry keys under `CurrentVersion` used by Windows for startup persistence. |
| **JSONL** | JSON Lines — one JSON object per line; easy to stream and ingest in SIEMs. |
| **Correlation** | Combining multiple events (e.g. same PID, same time window) to raise a higher-severity finding. |

---

## FAQ

**Q: Is LogSentry a replacement for an EDR or AV?**  
A: No. It is a **telemetry sensor** and **correlation/detection demo** for ETW. Use it for visibility, lab use, or as a building block alongside other security controls.

**Q: Can I run it without admin?**  
A: Partially. Process and DNS may work; Kernel-Registry and full process details often require elevation.

**Q: How do I reduce false positives?**  
A: Adjust the trusted process list (Registry Monitor), the DGA patterns/TLD list (DNS Monitor), and the parent-child/suspicious-parent list (Process Monitor) in the code to match your environment.

**Q: Where are logs stored?**  
A: By default in `%LocalAppData%\LogSentry`. Override with the first argument: `dotnet run -- "D:\Logs"`.

**Q: Can I export to a SIEM?**  
A: The JSONL output is machine-readable; you can point your SIEM or a log shipper (e.g. Filebeat, Winlogbeat) at the output directory to forward events.

---

## Security & Legal

- Use only on **systems you own or have explicit permission** to monitor.
- Do **not** use to evade or undermine security products or policies.
- This tool is for **defensive** and **educational** purposes (visibility, detection logic, ETW integration).

---

## Project Structure

```
LogSentry/
├── README.md                    # This file
├── LogSentry/
│   ├── LogSentry.csproj
│   ├── Program.cs               # Entry point, session setup, console wiring
│   ├── ProcessMonitor.cs        # Module 1: Kernel-Process, parent-child & temp anomalies
│   ├── DnsMonitor.cs            # Module 2: DNS-Client, DGA detection
│   ├── RegistryMonitor.cs       # Module 3: Kernel-Registry, Run/RunOnce, trust
│   ├── EventCorrelator.cs       # Module 4: Correlation, JSONL export, High Priority
│   └── Models/
│       └── SecurityEvent.cs     # ProcessStartEvent, DnsQueryEvent, RegistryWriteEvent, IncidentReport
```

---

**LogSentry** — real-time security telemetry and correlation over ETW.
