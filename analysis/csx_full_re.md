# CSX.exe — Full Reverse Engineering Report | DEV: XRAOUF

Blue-team deliverable. 100% static analysis (capstone disassembly + custom PE
parsers); the sample was never executed in this environment. Scope: the whole
chain, spoofer-focused, down to the decrypted payloads.

## 1. Sample identity
| | |
|---|---|
| File | `CSX.exe` (repo root) |
| SHA-256 | `683520631b81a7283e9d7c0870115867ed29630a782348119308d22eae1b6f31` |
| Size | 6,175,744 B |
| Format | PE32 native GUI (machine 0x014C), "CSX Loader", requireAdministrator |
| Timestamp | 2026-09-22T17:07:39Z |
| Sections | .text 0x376F9 (ent 6.48) · .mmap 0x245 · .rdata 0x109A0 (ent 5.23) · .data 0x1F08 · .fptable 0x80 · .rsrc 0x597638 (ent 7.87) · .reloc |
| Entry | RVA 0x22052 — MinGW CRT (CPUID "GenuineIntel" vendor check visible) |

## 2. Embedded resources
| Resource | Size | Header | Content |
|---|---|---|---|
| RCDATA 102 | 3,744,256 B | `0E6FE87E 5074656168746821 CDCF3236` ("Ptea hth!") | encrypted → **csxcheat.dll** |
| RCDATA 103 | 184,832 B | same 16B header | encrypted → **CSXAgent** (dropped csxprobe.exe / version.dll proxy) |
| RCDATA 104 | 1,791,148 B | PNG | UI artwork |
| Icons 1–4 · VERSION · MANIFEST | | | "CSX Loader" / admin manifest |

## 3. Loader mechanism (call sites = file-verified VAs, image base 0x400000)
- Resource access: `FindResourceW` @0x409DB8 (args: hModule=[0x44C978], id in cx, type=RCDATA) → `LoadResource` @0x409DCF → `LockResource` @0x409DDE → `SizeofResource` @0x409DED. (A parallel path @0x402E7D loads RCDATA 104 for the artwork → `GlobalAlloc/GlobalLock` → memcpy @0x423030 → `CreateStreamOnHGlobal` for GDI+.)
- **Decryption loop @0x409E30** (the whole cipher):
  `for (i = 0; i < size; ++i) buf[i] ^= key[i & 15];`
  with the 16-byte key stored at **VA 0x4463FC = `C5x~Stealth!2026`**
  (also independently derivable: header XOR standard DOS header `4D5A90000300000004000000FFFF0000`).
- Plaintext sanity check @0x409E48: `buf[0]=='M' && buf[1]=='Z'` and size ≥ 0x40.
- Drop: `CreateFileA(..., CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, GENERIC_WRITE)`
  with **4 retries × Sleep(600)** @0x409E62–0x409E92, then `WriteFile` @0x409EB6, `CloseHandle`.
- Target acquisition: `CreateToolhelp32Snapshot(2,0)` @0x409F11 + `Process32FirstW/NextW`
  loop comparing the exe name at 0x446254 (gta_sa.exe), PID returned to caller.
- Injection suite (classic CREATE_SUSPENDED manual map):
  `CreateProcessW` ×6 sites (0x405917, 0x408B04, 0x40C36A, 0x41AD76, 0x41BB5C, 0x41BD26),
  `VirtualAllocEx` @0x4021D6/0x4021F8/0x402370, `WriteProcessMemory` @0x40224B/0x4022BD/0x4023A5/0x4023BE,
  `CreateRemoteThread` @0x4023D6/0x40A711, `ResumeThread` @0x40C8DC; anti-debug
  `IsDebuggerPresent` @0x419959/0x42279D/0x428C34; module scan via `Module32FirstW/NextW`
  ("[ok] csxcheat.dll detected inside gta_sa.exe").
- Spoofer ("reset MTA serial identity"): rewrites `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
  (ADVAPI32 `RegSetValueExA`/`RegDeleteKeyA` imported), the **8 MTA identity keys**
  `SOFTWARE[\WOW6432Node]\Multi Theft Auto{: San Andreas All|: San Andreas|: Province All|}\{1.5,1.6}`,
  clears `C:\ProgramData\MTA San Andreas All\Common\data\cache`, keeps its own state under
  non-standard `Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID2`, and logs
  `[ok] done - your real hardware identity is back` (original identity saved → revertable).
- License/C2: WinHttp to `/api/event`, `}/api/heartbeat`, `/status?hwid=`, responses
  `{"banned":true,...}`, `locally banned`; fingerprint JSON template includes gpu/mb/disk +
  **discord_id/discord_name/discord_email**; updates from
  `raw.githubusercontent.com/onlyyoussef/csx-update` and `cdn.jsdelivr.net/gh/onlyyoussef/csx-update`;
  geolocation `ip-api.com`; invite `discord.gg/ehXCwMMFrM`; probes `C:\ProgramData:NT/NT2`
  alternate data streams; VM check string `virtual machine`.

## 4. Decrypted payloads
### PAYLOAD-102 — csxcheat.dll
| | |
|---|---|
| SHA-256 | `1026d3be16e37ce8aefa62148da71fe54afd54c6ca7ef3d4381e7f34be78869e` |
| Size | 3,744,256 B · PE32 DLL · base 0x10000000 · 6 sections (.text 0xD9BAA) |
| Imports | d3d9 (`Direct3DCreate9`), d3dx9_43 (texture loading), WINHTTP (full set), ADVAPI32 (`Reg*`, `CryptAcquireContextA/CryptCreateHash/CryptHashData/CryptGetHashParam` → hwid hashing; `CredDeleteW`), USER32 (`SetWindowsHookExW`, clipboard, `GetAsyncKeyState`), IMM32, ole32 (`CoCreateInstance` → WMI/Discord), SHELL32 |
| Identity | D3D9 overlay menu ("##MainMenuBar", "Menu Keybind", "Menu Opacity", PT/EN bilingual UI) |
| Capabilities (cleartext logs) | `[SILENTAIM] ProcessLineOfSight hooked` · `[SILENTAIM] SendBulletSyncFire hooked` · `[CLIENT] SendBulletSync hook enabled!` · `[ANTISCREEN] Server screenshot blocked!` + `TakePlayerScreenShot found: 0x%X` · `[TRIGGER] Block list is full (64)` · `PlayerTeleported` · money bag · `.lua` script dumping · `StoppedResources` |
| Discord harvesting | reads `\discord\sentry\scope_v3.json` (local Discord state) → feeds discord_id/name/email into the fingerprint JSON |

### PAYLOAD-103 — CSXAgent (dropped as csxprobe.exe / version.dll proxy)
| | |
|---|---|
| SHA-256 | `731854a7705d539eee41c47d22112f6e6aa34615b3b61723ec847a3ea0e269af` |
| Size | 184,832 B · PE32 DLL · base 0x10000000 |
| Exports | the 16 `version.dll` functions (GetFileVersionInfo*/VerQueryValue/…) → **DLL sideload proxy** |
| Imports | dbghelp (`MiniDumpWriteDump`, `StackWalk64`, `SymFromAddr`, `SymLoadModuleExW`), KERNEL32 (`WriteProcessMemory`, `VirtualProtect`, `TerminateProcess`, `RemoveVectoredExceptionHandler`, `RtlCaptureContext`) |
| PDB path (leak) | `C:\Users\dell\Downloads\all\freeesp\CSXAgent\bin\x86\csxagent.pdb` |
| Logged context | `EBP=%08lX ESP=%08lX EIP=%08lX EFlags=%08lX` (register capture = crash/monitor agent) |

## 5. Verdict for the player report
**Confirmed.** CSX.exe is a commercial-grade MTA spoofer + cheat loader:
it rotates the exact identity inputs (MachineGuid + MTA registry identity + cache)
that MTA client serials derive from, can restore them, injects `csxcheat.dll`
(silent aim / bullet-sync tampering / anti-screenshot / triggerbot) into the game,
and drops a `version.dll`-proxy agent. On a server, this defeats AC identity
tracking and blocks server screenshot AC checks.

## 6. DARKANARCHY countermeasures implemented (DLL-only)
- `nrth_csx.h`: 13-evidence signature table (container magic, the **XOR key itself**
  as a detectable artifact, loader log lines, spoofer JSON, CLSID2, and the
  decrypted-payload capability strings: silent-aim / anti-screenshot / triggerbot /
  Discord sentry / csxagent.pdb), ported `NrthCsx_DecryptXor16` for verification,
  fingerprint-JSON parity builder, display-only SIM generator.
- CSX AUDIT tab: read-only Identity Surface (MachineGuid, names, volume serial,
  MTA cache dir, MTA-key count, CLSID2), Artifact Detector (csxcheat.dll in-process,
  csxprobe.exe drops → verdict), display-only simulator.
- Lab procedure to close the report: scan baseline → run real CSX → rescan →
  delta (CLSID2 + drops + loaded module) = proof; suite sections 12–13 keep the
  detector in parity with this document (80/80 headless, 65/65 core-only).
- Not implemented by design: a live spoofer/injector clone (ban-evasion tooling).
