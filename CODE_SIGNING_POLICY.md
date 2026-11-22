# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

## What is signed

Only the Windows binaries of **win11-triage** built from this repository by GitHub Actions
(`.github/workflows/ci.yml`, job `build-exe`):

- `win11-triage-gui.exe`, `win11-triage.exe` (PyInstaller)
- `win11-triage-setup-<version>.exe` (Inno Setup installer)

Nothing built outside GitHub Actions, and no third-party binary, is signed with this certificate.
The Sysinternals tools are **not** redistributed: the installer can optionally fetch them from Microsoft via `winget`.

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [davidzabalaasir-create](https://github.com/davidzabalaasir-create) |
| Approvers | [davidzabalaasir-create](https://github.com/davidzabalaasir-create) |

All team members use multi-factor authentication on GitHub and SignPath.

## Release process

1. Changes reach `main` only through pull requests that pass CI (lint, tests on Windows and Linux,
   build, install/launch/uninstall smoke test).
2. A release is created by pushing a `v*` tag; CI builds the binaries and submits them to SignPath.
3. Each signing request is manually approved by an approver.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically
requested by the user or the person installing or operating it.

- **VirusTotal**: only when the user enables the VirusTotal module and provides their own API key,
  the SHA-256 hashes of suspicious files (never the files themselves) are sent to `www.virustotal.com`.
- **winget**: only when the user chooses to install the Sysinternals tools, `winget` downloads them from Microsoft.

No telemetry is collected.
