# Powershell-Scheduled-Tasks-UAC-Bypass

OSCP Project: Powershell script that bypasses UAC via Windows Task Scheduler

## Description

Powershell script that attempts to discover vulnerable scheduled tasks and perform privileged file execution via UAC bypass. 

To perform the bypass this script use the Environment Injection technique based on the Tyranid's Lair article: https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html. This process has been automated and performs the following functions:

- Identify the scheduled task that is weak to environment variable injection.
- Identify the name of the weak environment variable.
- Create the appropriate registry key for when the scheduled task is invoked.
- Runs the scheduled task and verifies that the UAC bypass has actually worked.

## Usage

```powershell
$ scheduled-tasks-uac-bypass -DiscoverOnly
```

```powershell
$ scheduled-tasks-uac-bypass -TaskName SilentCleanup -ExploitFile ".\exploit.ps1"
```
