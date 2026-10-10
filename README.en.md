# FileSharer

[한국어](README.md) | [English](README.en.md)

A C# Windows Forms application for sharing files and folders through links. It supports local network sharing and includes external sharing through an SSH relay or Tailscale Funnel.

## Features

- Share files and folders for browser downloads
- Share links, QR codes, folder browsing, and ZIP downloads
- PIN protection, expiration, download limits, and revocation
- Share management and access logs
- A Go helper for external sharing through Tailscale `tsnet`

## Source layout

| File | Purpose |
| --- | --- |
| `FileSharer.cs` | Windows Forms interface, HTTP server, share management, and external connections |
| `Setup.cs` | Windows installer |
| `tsproxy/main.go` | Helper connecting Tailscale Funnel to the local HTTP server |
| `tsproxy/go.mod`, `tsproxy/go.sum` | Go dependencies and integrity checksums |
| `filesharer.ico`, `filesharer_128.png` | Application icons |
| `build.ps1` | Builds the helper, application, and installer |

## Build

Use Windows with the .NET Framework 4.x C# compiler and Go installed. `tsproxy/go.mod` declares **Go 1.26.6**. Go can download the required version when automatic toolchain selection is enabled. The first build may require internet access to download the toolchain and dependencies.

Open PowerShell in the project directory and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

Outputs are written to `dist/`. `FileSharer.exe` embeds the compressed Go helper; `FileSharer_Setup.exe` embeds the application and icons. Run the application directly or use the installer. The build does not overwrite existing executables or live settings in the project root.

## Usage

1. Start the application and select an IP address and port. The default port is `3000`.
2. Add a file or folder and configure the PIN, expiration, and download limit as needed.
3. Share its link or QR code. Local links require network access to the server PC.
4. For external sharing, configure the selected connection method. The Tailscale option requires a valid authentication key and an account configured to allow Funnel.

External sharing makes the share address reachable from the internet. Review the shared content and access settings, and revoke links when finished. Keep authentication keys and actual access logs out of the repository.

## Public repository contents

This repository includes source code, icons, the build script, and documentation. Executables, installers, live settings, share databases, access logs, tunnel state, attachments, duplicate backups, and historical working notes are excluded. Existing local files are preserved.

## Licensing and dependencies

No separate open source license has been assigned to this project. Contact the repository owner for permission to redistribute, modify, or use it commercially. Go dependencies retain their respective licenses. See [dependency notes](THIRD_PARTY_NOTICES.md) and the [Tailscale license](third_party/tailscale.LICENSE).
