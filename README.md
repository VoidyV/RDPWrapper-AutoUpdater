# RDP Wrapper Universal Installer & Auto-Updater (Open Source)

[![Open Source](https://img.shields.io/badge/Open%20Source-100%25%20Auditable-brightgreen.svg)](./RDP-AutoUpdater.ps1)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Windows-10%20%7C%2011%2024H2-0078D6.svg)](#how-it-works)
[![Language](https://img.shields.io/badge/Code-PowerShell%20%26%20Batch-5391FE.svg)](#quick-start)

A lightweight, **100% open-source** installer and dynamic memory-signature auto-updater for **RDP Wrapper Library v1.6.2**. Automatically installs RDP Wrapper on clean systems and dynamically patches `rdpwrap.ini` for **Windows 10** and **Windows 11 (including 24H2 build `10.0.26100.9818` and newer updates)** by scanning `termsrv.dll` directly—with zero compiled third-party executables.

---

## Why Open Source & Plain-Text?

Every line of logic in this repository is published as **human-readable, plain-text source code** (`RDP-AutoUpdater.ps1` and `RDP-AutoUpdater.bat`) under the **MIT License**, allowing system administrators, developers, and security auditors to inspect every registry key, PE offset calculation, and service restart before execution.

---

## Problems Solved

- **`Listener state: Listening [not supported]`** after Windows Updates.
- **`"The number of connections to this computer is limited"`** / concurrent RDP session limit on Windows 10 & Windows 11 (Home / Pro).
- **Windows 11 24H2 (`26100.xxxx`) Session Limit Bug:** Windows 11 24H2 changed the `CDefPolicy::Query` prologue from `8B 87` to `44 8B 87`. Because `rdpwrap.dll` v1.6.2's legacy signature skips patching on 24H2, this script locates the conditional jump (`75`) dynamically and applies a native `jmpshort` patch.

---

## Quick Start

### Option 1: 1-Click Batch Launcher (`RDP-AutoUpdater.bat`)
1. Download **`RDP-AutoUpdater.bat`** from this repository.
2. Double-click the file and approve the **Administrator (UAC)** prompt.

### Option 2: Standalone PowerShell Script (`RDP-AutoUpdater.ps1`)
1. Download **`RDP-AutoUpdater.ps1`**.
2. Run in an elevated PowerShell terminal:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force; .\RDP-AutoUpdater.ps1
   ```

### Expected Output
```text
[+] RDP Wrapper configured and TermService restarted! (10.0.26100.9818)
    Wrapper state : Installed
    Service state : Running
    Version patch : [fully supported]
```

---

## How It Works

| Patch Target | Method / Instruction | Verified Offset (`10.0.26100.9818`) |
| :--- | :--- | :--- |
| `LocalOnlyPatch.x64` | `jmpshort` | `0009FA61` |
| `SingleUserPatch.x64` | `Zero` | `000CD8B4` |
| `DefPolicyPatch.x64` | `jmpshort` (Win11 24H2+) / `CDefPolicy_Query_eax_rdi` (Win10/11 23H2) | `000A9787` |
| `SLInitHook.x64` | `New_CSLQuery_Initialize` + dynamic `-SLInit` structure RVAs | `000C0798` |

- **Automatic Backup:** Saves `rdpwrap.ini.bak` before modifying any configuration.
- **Policy & Firewall:** Configures `fSingleSessionPerUser = 0`, `MaxInstanceCount = 999999`, `fDenyTSConnections = 0`, and enables the Windows Firewall Remote Desktop rule group (`TCP/UDP 3389`).

---

## Contributing & License

- Contributions and new Windows build signature reports are welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md).
- Licensed under the **MIT License** — see [LICENSE](./LICENSE).
- Core RDP Wrapper library by [stascorp/rdpwrap](https://github.com/stascorp/rdpwrap) (`v1.6.2`).