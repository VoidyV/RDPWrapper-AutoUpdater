# Contributing to RDPWrapper-AutoUpdater

Thank you for helping keep this open-source project compatible with new Windows builds!

## Reporting a New Windows Build / Signature Mismatch
If a future Windows update changes `termsrv.dll` signatures, please open an **Issue** with:
1. Your Windows edition and build number (e.g., `Windows 11 Pro 24H2 26100.xxxx`).
2. The exact `termsrv.dll` file version shown in the terminal output.

## Submitting Pull Requests
- Keep all scripts **100% plain-text** (`.ps1` and `.bat`) with no pre-compiled binaries.
- Test changes in a clean **Windows Sandbox** environment before submitting.