# Powershell-Scheduled-Tasks-UAC-Bypass

OSCP Project: Powershell script that bypasses UAC via Windows Task Scheduler

## Description

Powershell script that attempts to discover vulnerable scheduled tasks and perform privileged file execution via UAC bypass.

## Usage

```powershell
$ scheduled-tasks-uac-bypass -DiscoverOnly
```

```powershell
$ scheduled-tasks-uac-bypass -TaskName SilentCleanup -ExploitFile ".\exploit.ps1"
```
