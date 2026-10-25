# Evidence Collector

## Avertissement Juridique / Legal Disclaimer

**FR :** Cet outil est une solution logicielle open-source conçue pour répondre aux exigences techniques de la norme AFNOR NF Z67-147. Pleinement fonctionnel et développé pour garantir une fiabilité technique optimale, ce logiciel constitue une aide à la collecte. Conformément à la législation française, seul un officier public ou ministériel (notamment le Commissaire de justice) est habilité à dresser un procès-verbal de constat doté d'une force probante devant les tribunaux. Les auteurs déclinent toute responsabilité quant à l'usage, l'interprétation ou les suites données à l'utilisation de cet outil dans le cadre de procédures ou de litiges réels.

**EN :** This tool is an open-source software solution designed to meet the technical requirements of the AFNOR NF Z67-147 standard. Fully functional and developed to ensure optimal technical reliability, this software serves as a collection aid. In accordance with French law, only a public or ministerial officer (specifically a Commissaire de justice) is authorized to draw up an official report (procès-verbal de constat) possessing evidentiary value before French courts. The authors disclaim all liability for the use, interpretation, or consequences arising from the use of this tool in the context of legal proceedings or actual disputes.

![EvidenceCollector Logo](ico/EvidenceCollector.jfif)

---

Windows desktop tool (C# / .NET 10, WinForms + Microsoft Edge WebView2) that guides a bailiff / *commissaire de justice*
through the **four phases** of an internet evidence collection inspired by **AFNOR NF Z67-147**, and produces a
sealed, verifiable evidence package.

> **Scope.** The tool implements a technical workflow and records what is needed to demonstrate it. It does not itself
> certify compliance with the standard: the officer performing the collection remains responsible for the method
> followed and for the official record (procès-verbal). The same notice is shown in the application (*About*).

* UI, logs, tooltips and messages: English (en-US).
* All settings live in `config.json` (next to the executable). Comments and trailing commas are allowed.
* No telemetry. The only outgoing connections are the ones the collection needs: the visited site, NTP servers,
  the public-IP endpoints, WHOIS / RDAP.

---

## 1. Requirements

| | |
|---|---|
| OS | Windows 10 or Windows 11, x64 or ARM64 |
| SDK (to build) | **.NET 10 SDK** (Visual Studio 2026 includes it) |
| Runtime (to run) | .NET 10 Desktop Runtime *or* a self-contained publish (see §3) |
| Browser engine | **Microsoft Edge WebView2 Runtime** (Evergreen; already present on Windows 11 and most Windows 10 machines) – <https://developer.microsoft.com/microsoft-edge/webview2/> |
| Network | Outbound UDP 123 (NTP), TCP 43 (WHOIS) and HTTPS. A blocked NTP or WHOIS port is reported, not hidden. |

---

## 2. Project structure

```
EvidenceCollector/
├─ EvidenceCollector.csproj      net10.0-windows, WinForms, WebView2 package, config.json copied to the output
├─ Program.cs                    entry point: --config <path>, crash dialog + crash.log
├─ config.json                   every setting, at its default value, with comments
├─ config.schema.json            JSON schema for editor validation / auto-complete
│
├─ Config/
│  ├─ AppConfig.cs               typed model of config.json (every property has a safe default)
│  └─ ConfigManager.cs           load, clamp out-of-range values, patch the theme in place, SHA-256 of the file
│
├─ Core/                         platform-neutral engine (also covered by the smoke tests)
│  ├─ HashEngine.cs              streamed SHA-256 / SHA-512, one pass per file, pooled buffers
│  ├─ AuditLog.cs                append-only, hash-chained audit trail (audit.jsonl + audit.log)
│  ├─ Session.cs                 SessionContext, EvidenceRegistry (hash at creation), phase status
│  ├─ NtpClient.cs, TimeSync.cs, TrustedClock.cs, ClockCheck.cs
│  │                             SNTP, several servers, median offset; the PC clock is never changed
│  ├─ EnvironmentChecker.cs      system, config, tool integrity, disk, temp, proxy, VPN, hosts file
│  ├─ NetworkDiagnostics.cs      adapters (ipconfig data), DNS servers, public IP by consensus, raw ipconfig / netsh
│  ├─ NetworkPhaseRunner.cs      Phase 2 orchestration
│  ├─ TargetDiagnostics.cs       DNS answer, TLS handshake and certificate, optional traceroute for the target host
│  ├─ WhoisClient.cs, WhoisCoordinator.cs      WHOIS (port 43, IANA referral) with RDAP fallback; domain + IP
│  ├─ UrlValidator.cs            scheme allow-list, normalisation, optional private-address block
│  ├─ SecureTemp.cs              per-session private temp folder, best-effort overwrite + delete
│  └─ PhaseReports.cs, Models.cs, JsonUtil.cs, NetUtil.cs, AppInfo.cs
│
├─ Browser/
│  ├─ EvidenceBrowser.cs         WebView2 wrapper: InPrivate profile, direct connection, no cache, no downloads,
│  │                             permissions denied, one window, scheme allow-list, full navigation audit
│  ├─ NetworkRecorder.cs         DevTools-protocol journal of every request / response (cookie values masked)
│  ├─ PreparationRunner.cs       Phase 1 orchestration (checks + neutralisation of the browser data)
│  └─ PageScripts.cs
│
├─ Capture/
│  ├─ CaptureService.cs          Phase 3 captures (see §4); each part fails independently into a recorded warning
│  └─ ScreenshotStamper.cs       information band / watermark: URL, UTC + local time, case, operator, session
│
├─ Sealing/
│  ├─ SealEngine.cs              Phase 4: NTP, re-hash of everything, report, manifest, receipt, ZIP, verification
│  ├─ ManifestVerifier.cs        stand-alone verification of a sealed package
│  ├─ ReportGenerator.cs         self-contained, HTML-encoded report (annex of the procès-verbal)
│  └─ SealModels.cs
│
├─ UI/
│  ├─ MainForm.Designer.cs       ALL controls (Visual Studio designer compatible)
│  ├─ MainForm.cs                behaviour only: phase gating, running the engine, showing results
│  ├─ Theme.cs                   dark / light corporate theme, owner-drawn lists, title bar
│  └─ HeaderlessTabControl.cs    tab control without its tab strip (the phase navigation drives it)
│
└─ tests/CoreSmokeTests/         platform-neutral smoke tests (57 checks, see §7)
```

---

## 3. Build and run

### Command line

```powershell
# from the folder that contains EvidenceCollector.csproj
dotnet --version                       # must be 10.x
dotnet restore
dotnet build -c Release
dotnet run -c Release                  # or:  .\bin\Release\net10.0-windows\EvidenceCollector.exe
dotnet run -c Release -- --config D:\cases\my-config.json     # alternative configuration file
```

### Visual Studio

Open `EvidenceCollector.csproj` (or the folder) in a Visual Studio version that supports .NET 10, restore the NuGet
package (`Microsoft.Web.WebView2`), then **F5**. `UI\MainForm.cs` opens in the Windows Forms designer: every control
is created in `MainForm.Designer.cs`, so the layout can be edited visually and saved without touching the logic.
Control names (`btnRunPrep`, `listEvidence`, …) are used by `MainForm.cs`; keep them when you rename or move controls.

### Publish

```powershell
# self-contained (nothing to install except the WebView2 runtime)
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Do not enable trimming (WinForms + reflection-based JSON). `config.json` and `config.schema.json` are copied next to
the executable; edit `publish\config.json` for the target PC. If `config.json` is missing and the folder is not
writable (e.g. `Program Files`), a default one is created in `%LOCALAPPDATA%\EvidenceCollector\config.json`.

### First start

1. Page **0 Session**: case reference, operator, office, purpose → **Start session**. The clock is synchronised, the
   session folder and audit log are created, the evidence browser starts.
2. Follow phases **1 → 4** with the buttons on the left. A phase opens only when the previous one passed
   (`workflow.enforcePhaseOrder`).

---

## 4. The four phases

| Phase | What the application does | What is written to the package |
|---|---|---|
| **0 Session** | NTP synchronisation, session folder, audit log, snapshot of `config.json` and of the configuration in force | `00_session/` |
| **1 Preparation and neutralisation** | Checks the workstation (system, config file, tool integrity, free disk, temp folder, **clock**, **system proxy**, **VPN / tunnel adapters**, hosts file). Clears cache, cookies, local / session storage, IndexedDB, service workers, history and autofill of the evidence browser, resets its history, then **verifies** the result (cookie count before / after). The browser runs InPrivate, with `--no-proxy-server`, with the HTTP cache disabled. Proxy / VPN findings are shown in a banner (policy: `Ignore`, `Warn` or `Block` in `config.json`). | `01_preparation/` |
| **2 Network configuration and diagnostics** | Local IP configuration (adapters, IPv4 / IPv6, gateways, MAC), **active DNS servers**, **public IP** confirmed by several independent HTTPS endpoints, literal output of `ipconfig /all` and `netsh winhttp show proxy`, NTP reference time, WHOIS / RDAP holder of the public IP. | `02_network/` |
| **3 Controlled navigation and capture** | Validated URL bar; one window; downloads and permission prompts refused; every navigation (including redirects and blocked ones) recorded. Capture buttons: **viewport** and **full-page screenshots** (information band with URL, UTC time, case and operator, plus diagonal watermark; the untouched PNG is kept), **source** (raw HTTP response body, response headers and redirect chain, rendered DOM, visible text, every CSS file as received, CSSOM), **archive** (MHTML + PDF), **connection** (DNS answer, TLS handshake and certificate chain obtained by the workstation, cookies, full request journal) and **WHOIS / RDAP** of the domain and of the server address. **Re-neutralise browser…** cleans the browser between two unrelated sites. Optional automatic capture after each page load. The page is locked against navigation while a capture runs, so it describes one single state. | `03_captures/<n>_<host>_<UTC>/`, `04_whois/` |
| **4 Closing, integrity and sealing** | Final NTP synchronisation (the official sealing time); every registered file is **re-hashed** and compared with the fingerprint taken when it was created; an unregistered or modified file **stops the seal**; HTML report; audit log closed; `manifest.json`, `manifest.sha256`, receipt, optional ZIP + its SHA-256; files marked read-only; the sealed package is re-verified. | `05_sealing/`, `<session>.zip` |

### Timestamps

Every timestamp is the NTP-corrected UTC time **and** the raw PC clock is recorded next to it with the measured
offset, so the correction can be audited. The PC clock itself is never modified. If NTP cannot be reached the
application says so (`workflow.requireNtpSync` decides whether that blocks the phase or only warns).

### Session folder

```
<outputRoot>\EVC-20261024-101530-a1b2_<case>\
├─ 00_session\   session.json, config_snapshot.json, config_effective.json, navigation_trail.json
├─ 01_preparation\ 02_network\ 04_whois\
├─ 03_captures\0001_example.com_20261024T101712Z\   screenshots, source_*, css\, page_snapshot.mhtml, page_print.pdf,
│                                                    connection.json, cookies.json, network_resources.json, capture.json …
├─ audit\        audit.jsonl (hash chain), audit.log (readable)
└─ 05_sealing\   manifest.json, manifest.sha256, SEAL_RECEIPT.txt, report.html
<outputRoot>\EVC-…_<case>.zip  and  .zip.sha256
```

**Write the `manifest.json` SHA-256 (shown at the end of Phase 4 and in `SEAL_RECEIPT.txt`) in the procès-verbal.**
It fingerprints the whole package.

### Verifying a sealed package later

* In the application: page **0 Session → Verify a package…** (works without starting a session), or **Re-verify this package** on page 4.
* Without the application: `manifest.sha256` is in `sha256sum` format → `sha256sum -c manifest.sha256`
  (Git Bash / WSL) or `Get-FileHash -Algorithm SHA256 <file>` in PowerShell.
* The audit log is a hash chain: each entry commits to the previous one, and the head hash is sealed in the manifest,
  so an inserted, edited, deleted or truncated entry is detected.

---

## 5. `config.json`

The file is complete: every option is present at its default value, with a comment. `config.schema.json` gives
validation and auto-complete in Visual Studio / VS Code (the `$schema` line at the top).

| Section | Controls |
|---|---|
| `ui` | `theme` (`Dark` / `Light`, also toggled by the header button, which patches this value in place and keeps your comments), `showAuditPanel` |
| `paths` | `outputRoot` (sessions), `tempRoot` (private browser profile, wiped at the end), `webViewRuntimeFolder` (fixed-version runtime). `%ENV%` variables are expanded |
| `session` | defaults for the session form, `requireCaseReference`, `requireOperatorName`, `sessionIdPrefix` |
| `workflow` | `enforcePhaseOrder`, `proxyPolicy` / `vpnPolicy` / `hostsFilePolicy` (`Ignore` / `Warn` / `Block`), `requirePublicIp`, `requireNtpSync`, `minimumFreeDiskMb` |
| `neutralization` | which browsing data Phase 1 clears, secure wipe of temporary files |
| `network` | public-IP endpoints (HTTPS only) and agreement threshold, timeouts, VPN adapter keywords, traceroute limits |
| `ntp` | servers, timeout, samples per server, minimum responses, maximum tolerated PC-clock error |
| `webView` | direct connection, InPrivate, cache, language, popup policy, allowed schemes, private-address block, downloads, DevTools, context menu, user agent, journal size |
| `capture` | screenshot (tiles, auto-scroll, overlay), source, archive (MHTML / PDF, paper size), cookies (values are **not** stored by default), automatic capture, domain record (WHOIS / DNS / TLS / traceroute) |
| `whois` | IANA server, port, timeouts, RDAP fallback |
| `hashing` | `SHA256` always; add `SHA512` for a second digest; buffer size |
| `sealing` | ZIP, verification after sealing, read-only files, report title / organisation, thumbnails |
| `logging` | flush every entry, readable log, number of rows kept in the UI |

Out-of-range values are clamped and **every adjustment is listed** in a dialog at start-up. A file that cannot be
parsed is never overwritten: built-in defaults are used until it is fixed. The configuration actually in force is
saved in the package (`config_effective.json`, with a copy of the file as it was: `config_snapshot.json`).

---

## 6. Security and resource notes

* **Isolation** – the browser profile lives in a per-session folder under `paths.tempRoot` (restricted to the current
  user on NTFS), InPrivate, no autofill / password saving, no SSO with the Windows account, DevTools and context menu
  off, downloads refused, permissions denied, `javascript:` / `file:` / `data:` / `ftp:` URLs refused, pop-ups without a
  user gesture refused. At the end of the session the profile is overwritten (best effort, single pass; not guaranteed
  on SSD or copy-on-write volumes) and deleted. Profiles left behind by a crashed session (older than one day) are removed at the next start.
* **Integrity** – streamed hashing (one pass, pooled buffer, no whole-file reads), hash at creation then full re-hash
  at sealing, hash-chained audit log flushed to disk entry by entry, read-only files after sealing.
* **Secrets** – cookie values and credentials are masked in the request journal; cookie values are not written unless
  `capture.cookies.storeCookieValues` is `true`.
* **Footprint** – workstation, non-concurrent GC; response bodies kept in memory are bounded
  (`capture.source.maxCachedBodyMb`); the browser trims its memory while minimised; the UI audit list is capped.
  The heavy parts (hashing, image stamping, ZIP) run on the thread pool; the UI thread only drives WebView2.

---

## 7. Tests and what has been verified

`tests/CoreSmokeTests` links the platform-neutral sources and runs on any OS:

```powershell
dotnet run --project tests/CoreSmokeTests          # 57 checks, exit code 0 = all passed
```

It covers hashing (FIPS vectors), NTP maths and a fake NTP server, URL validation, `config.json` loading / clamping,
the audit chain (edit, delete, truncate), a full session → seal → verify cycle (including the refusal to seal a
modified or unregistered file) and tamper detection on the sealed package.

---

## 8. Troubleshooting

| Symptom | Cause / action |
|---|---|
| "The Microsoft Edge WebView2 Runtime is not installed" | Install the Evergreen runtime, restart the application. |
| Phase 1 or the clock check **fails** | NTP unreachable (firewall on UDP 123). Fix it, or set `workflow.requireNtpSync` to `false` to downgrade it to a warning – the PC clock is then used and the report says so. |
| Proxy / VPN warning | The connection may not be direct. Disconnect and run Phase 1 again, or justify it in the procès-verbal. `workflow.proxyPolicy` / `vpnPolicy` set the severity. |
| "Capture completed with warnings" | One part (for example the PDF) failed; the others were saved and the gap is recorded in `capture.json` and the audit log. |
| Seal refused: "a file was modified / is not registered" | Something touched the session folder after it was captured. Remove the stray file or restore the original, then seal again. |
| `config.json` ignored | The file has a syntax error: the start-up dialog shows it and defaults are in use. |
