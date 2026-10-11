# CSX.exe — Spoofer Feature Analysis (evidence-based) | DEV: XRAOUF

Blue-team analysis for report verification. **Scope: the spoofer feature only.**
All findings below were extracted statically from the supplied binary; nothing
was executed.

## Sample identity
| Field | Value |
|---|---|
| File | `CSX.exe` (repo root) |
| Size | 6,175,744 bytes |
| SHA-256 | `683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31` |
| Format | PE32 native (machine 0x014C, not .NET), GUI subsystem |
| Version info | FileDescription **"CSX Loader"**, OriginalFilename `CSX.exe` |
| Manifest | `requestedExecutionLevel level='requireAdministrator'` (admin rights) |
| Timestamp | 2026-09-22T17:07:39Z |
| Layout | .text 0x376F9; **.rsrc 0x597638 (~5.86 MB = 95% of file)**; odd sections `.mmap`, `.fptable` |

## Embedded payloads (resources)
| Resource | Size | Header | Meaning |
|---|---|---|---|
| RCDATA 102 | 3,744,256 B | `0E 6F E8 7E 50 74 65 61 68 74 68 21 ...` | encrypted container ("Ptea hth!" magic), entropy 7.93/8.0 |
| RCDATA 103 | 184,832 B | same 16-byte header | second encrypted container, entropy 7.64 |
| RCDATA 104 | 1,791,148 B | `89 50 4E 47` (PNG) | UI artwork |
| Icons 1–4, VERSION, MANIFEST | — | — | standard |

No single-byte XOR reveals `MZ`; the containers are properly encrypted/packed
(the loader references the payload name in cleartext — see below).

## The spoofer feature — what the evidence shows
1. **Identity fingerprinting (reads)** — `.rdata` JSON template:
   `{"type":"%s","hwid":"%s","computer":"%s","user":"%s","gpu":"%s","mb":"%s","disk":"%s","version":"%s","discord_id":"%s","discord_name":"%s","discord_email":"%s"}`
   fed by WMI (`ROOT\CIMV2`): `Win32_VideoController.Name` (GPU),
   `Win32_BaseBoard.SerialNumber` (motherboard), `Win32_DiskDrive.SerialNumber`
   (disk), `Win32_ComputerSystem.Manufacturer/Model`, `Win32_BIOS.Manufacturer`,
   plus `MachineGuid` from `HKLM\SOFTWARE\Microsoft\Cryptography` and
   `GetComputerNameW`. It also harvests the local **Discord** account
   (id/name/email) — privacy-invasive telemetry.
2. **License/C2 network (WinHttp)** — `/api/event`, `}/api/heartbeat`,
   `/status?hwid=`, ban check responses `"banned":true`, `"locally banned"`;
   update CDN `raw.githubusercontent.com/onlyyoussef/csx-update/main/CSX.exe` and
   `cdn.jsdelivr.net/gh/onlyyoussef/csx-update@main/CSX.exe`; geolocation via
   `ip-api.com`; invite `https://discord.gg/ehXCwMMFrM`.
3. **The spoof itself ("reset MTA serial identity")** — cleartext log lines:
   `Resetting MTA serial...`, `[info] resetting MTA serial identity...`,
   `[ok] done - your real hardware identity is back` ( ⇒ it saves the original
   identity and can **revert**). Registry surface it touches:
   - `HKLM\SOFTWARE\Microsoft\Cryptography` → **MachineGuid** (the primary
     Windows machine identity feeding MTA's client serial);
   - the MTA identity keys ×8:
     `SOFTWARE[\\WOW6432Node]\Multi Theft Auto{: San Andreas All|: San Andreas|: Province All|}\1.5/1.6`;
   - its own state/persistence under the **non-standard**
     `Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID2`;
   - clears `C:\ProgramData\MTA San Andreas All\Common\data\cache`.
4. **Injection** — `csxcheat.dll` mapped into a suspended `gta_sa.exe` before
   resume (`[ok] csxcheat.dll mapped before gta_sa.exe resume`), a `version.dll`
   proxy name, dropped probe `csxprobe.exe` (Windows\Temp, ProgramData,
   Users\Public, and **RDP shares** `\\tsclient\...`), plus a "rescue" path if
   the game closes first. `C:\ProgramData:NT`/`:NT2` alternate data streams and
   `virtual machine` string (VM checks) round out the loader behavior.

## Conclusion (for the player report)
The report is **technically plausible**: CSX.exe is an MTA-identity spoofer
loader — it rotates the identity inputs (MachineGuid + MTA registry identity +
cache) that MTA clients derive their serial from, can restore them, and injects
a payload DLL into the game. It is ban-evasion tooling; on a server it changes
what AC sees as the client identity.

## DARKANARCHY response (this repo, DLL-only)
`nrth_csx.h` + the **CSX AUDIT** tab implement the *authorized* counterpart:
- **Identity Surface (read-only)**: shows locally the exact fields CSX targets
  (MachineGuid, computer/user, volume serial, MTA cache dir, the 8 MTA keys,
  CLSID2 presence). No writes anywhere.
- **CSX Artifact Detector**: flags `csxcheat.dll` loaded in-process,
  `csxprobe.exe` drops, and the `CLSID2` state key → verdict for the lab.
- **Spoof Simulator (display-only)**: deterministic local token transform,
  labeled `SIM-…`, never applied — a live spoofer is ban evasion and is NOT
  implemented in this DLL.
- Signature constants (payload magic, artifact names, JSON templates, endpoints)
  are embedded and unit-tested (suite section 12) so the detector stays in
  parity with this analysis.
