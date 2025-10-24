# UsbIpdTool - USB to WSL Helper

UsbIpdTool is a PowerShell script for Windows that simplifies the process of attaching USB devices to WSL2 using [UsbIpd](https://github.com/dorssel/usbipd-win).

> [Connect USB devices to WSL2](https://learn.microsoft.com/en-us/windows/wsl/connect-usb)

## Usage

1. Connect your USB device to the Windows host.
2. Run the `UsbIpdTool.ps1` script to attach the USB device to WSL2.
3. Access the USB device from within your WSL2 environment.

## Linting

```powershell
# Install once (per-user)
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber

# Run analyzer from the repo root
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

## Dev Container Setup

Example setup of Dev Container for VS Code using Docker Compose.

- `.devcontainer/Dockerfile`

```Dockerfile
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    usbutils \
    udev \
    && rm -rf /var/lib/apt/lists/*
```

- `.devcontainer/devcontainer.json`

```json
{
    "name": "Compose Project",
    "dockerComposeFile": "docker-compose.yml",
    "service": "devcontainer",
    "workspaceFolder": "/workspace"
}
```

- `.devcontainer/docker-compose.yml`

```yaml
services:
  devcontainer:
    build:
      context: .
      dockerfile: Dockerfile
    hostname: devcontainer
    container_name: compose-project-devcontainer
    privileged: true
    user: vscode
    group_add: [ "dialout", "plugdev" ]
    devices:
      - /dev/bus/usb:/dev/bus/usb
    volumes:
      - ..:/workspace
    command: sleep infinity
```

## Requirements

- Requires [UsbIpd-Win](https://github.com/usbipd/usbipd-win) 5.2.0 or later to be installed
- Requires WSL2 to be installed and configured.

---

![License: MIT License](https://img.shields.io/badge/License-mit-blue.svg)
