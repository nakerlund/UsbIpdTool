<#
.SYNOPSIS
	Forwards USB devices to WSL and containers using usbipd-win.

.DESCRIPTION

	Makes USB devices accessible in dockers and dev containers.

	MIT License, available on https://github.com/nakerlund/UsbIpdTool

	Requires:
	- usbipd-win >= 5.2.0
	- PowerShell 5.1+ (included in Windows 11)

	Features:
	- Simple interactive TUI for usbipd-win.
	- Binds and unbinds automatically for WSL and containers.
	- Requests privilege elevation as needed.
	- Requires usbipd-win >= 5.2.0
	- Requires PowerShell 5.1+, which is included in Windows 11.

	Keys:
	- [A] = Attach once (BusId preferred, HW fallback)
	- [B] = Attach and auto reattach by BusId (The USB Port)
	- [H] = Attach and auto reattach by Hardware Id
	- [D] = Detach & Unbind
	- [R] = Reset all
	- (Use Ctrl+C to exit)

.PARAMETER Version
	Show tool version and exit.
	This is a switch parameter (no value expected). Use `-Version` or `-v` to print
	the script version and return.

#>

#Requires -Version 5.1

[CmdletBinding()]
param(
	[Parameter(HelpMessage = 'Show script version')]
	[Alias('v')]
	[switch]
	$Version
)

try
{
	[Console]::OutputEncoding = [Text.Encoding]::UTF8
}
catch
{
	Write-Verbose "Ignored: $($_.Exception.Message)"
}

try
{
	chcp 65001 | Out-Null
}
catch
{
	Write-Verbose "Ignored: $($_.Exception.Message)"
}


$script:ToolVersion = '1.0.0'
if ($Version)
{
	Write-Output "UsbIpdTool $script:ToolVersion"
	return
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Symbols
$Check = [char]0x2713  # ✓
$Cross = [char]0x2717  # ✗

# Wait constants
$STATE_TIMEOUT_MS = 2000
$STATE_POLL_MS = 200

# ---------- Exec helpers ----------
function Invoke-External
{
	param(
		[Parameter(Mandatory)][string]$Executable,
		[string[]]$ArgumentList = @(),
		[switch]$Capture
	)
	try
	{
		if ($Capture)
		{
			$out = @(& $Executable @ArgumentList 2>&1)
			$code = if ($null -ne $global:LASTEXITCODE)
			{
				$global:LASTEXITCODE
			}
			else
			{
				0
			}
			return [pscustomobject]@{ ExitCode = $code; Output = $out }
		}
		else
		{
			& $Executable @ArgumentList
			$code = if ($null -ne $global:LASTEXITCODE)
			{
				$global:LASTEXITCODE
			}
			else
			{
				0
			}
			return [pscustomobject]@{ ExitCode = $code; Output = @() }
		}
	}
	catch
	{
		Write-Host "$Cross $($_.Exception.Message)" -ForegroundColor Red
		return [pscustomobject]@{ ExitCode = 1; Output = @() }
	}
}

function Invoke-UsbipdElevated
{
	<#
    .SYNOPSIS
      Elevate `usbipd` on PS 5.1 and capture output via a wrapper script.

    .OUTPUTS
      PSCustomObject { ExitCode:int; Output:string[] }
    #>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string[]]$UsbipdArgs,
		[int]$TimeoutSec = 30
	)

	# Temp paths
	$guid = [guid]::NewGuid().ToString('N')
	$logFile = Join-Path ([IO.Path]::GetTempPath()) "usbipd-elev-$guid.log"
	$wrapperPs = Join-Path ([IO.Path]::GetTempPath()) "usbipd-elev-$guid.ps1"

	# Build a PS array literal of quoted args to preserve spaces and special chars
	$quoted = $UsbipdArgs | ForEach-Object {
		# Escape backticks and quotes for double-quoted PS strings
		$_.Replace('`', '``').Replace('"', '`"')
	}
	$arrayLiteral = ($quoted | ForEach-Object { '"{0}"' -f $_ }) -join ', '

	# Wrapper: run usbipd, capture stdout+stderr, write UTF-8 log, exit with same code
	$wrapper = @"
`$ErrorActionPreference = 'Continue'
`$argsArray = @($arrayLiteral)
`$all = & usbipd @argsArray 2>&1 | ForEach-Object { `$_ | Out-String }
`$all | Set-Content -LiteralPath '$logFile' -Encoding UTF8
`$code = if (`$LASTEXITCODE -ne `$null) { [int]`$LASTEXITCODE } else { 0 }
exit `$code
"@

	try
	{
		Set-Content -LiteralPath $wrapperPs -Value $wrapper -Encoding UTF8

		# Elevate PowerShell to run the wrapper. Do NOT use output redirection here.
		$p = Start-Process -FilePath 'powershell.exe' `
			-ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $wrapperPs) `
			-Verb RunAs -PassThru

		if (-not $p.WaitForExit($TimeoutSec * 1000))
		{
			try
			{
				$p.Kill()
			}
			catch
			{
				Write-Verbose "Ignored: $($_.Exception.Message)"
			}
			return [pscustomobject]@{ ExitCode = 1; Output = @("Timed out after $TimeoutSec s") }
		}

		# Read captured output
		$out = @()
		if (Test-Path -LiteralPath $logFile)
		{
			try
			{
				$out = Get-Content -LiteralPath $logFile -Encoding UTF8
			}
			catch
			{
				$out = @("Failed to read log: $($_.Exception.Message)")
			}
		}

		return [pscustomobject]@{ ExitCode = [int]$p.ExitCode; Output = $out }
	}
	catch
	{
		return [pscustomobject]@{ ExitCode = 1; Output = @("Elevation failed: $($_.Exception.Message)") }
	}
	finally
	{
		foreach ($f in @($wrapperPs, $logFile))
		{
			try
			{
				if (Test-Path -LiteralPath $f)
				{
					Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
				}
			}
			catch
			{
				Write-Verbose "Ignored: $($_.Exception.Message)"
			}
		}
	}
}

# ---------- usbipd state ----------
function Get-UsbipdVersion
{
	$ver = Invoke-External 'usbipd' @('--version') -Capture
	$line = if ($ver.ExitCode -eq 0 -and $ver.Output.Count -gt 0)
	{
		$ver.Output[0]
	}
	else
	{
		''
	}
	$m = [regex]::Match($line, '\d+(\.\d+){1,3}')
	if ($m.Success)
	{
		return $m.Value
	}
	else
	{
		return '0'
	}
}

function Get-DevicesRaw
{
	$res = Invoke-External 'usbipd' @('state') -Capture
	if (-not ($res -and $res.ExitCode -eq 0))
	{
		throw "usbipd state failed (exit $($res.ExitCode))."
	}
	$json = (@($res.Output) -join "`n").Trim()
	if ([string]::IsNullOrWhiteSpace($json))
	{
		throw 'usbipd state returned empty output.'
	}
	$parsed = $json | ConvertFrom-Json
	if ($parsed.PSObject.Properties.Match('Devices').Count)
	{
		return @($parsed.Devices)
	}
	if ($parsed -is [System.Collections.IEnumerable] -and $parsed -isnot [string])
	{
		return @($parsed)
	}
	throw 'usbipd state JSON did not contain a device array.'
}

function Get-VidPid
{
	param([string]$InstanceId)
	if (-not $InstanceId)
	{
		return $null
	}
	$m = [regex]::Match($InstanceId, 'VID[_:-]?([0-9A-Fa-f]{4}).*PID[_:-]?([0-9A-Fa-f]{4})')
	if ($m.Success)
	{
		return ('{0}:{1}' -f $m.Groups[1].Value.ToUpper(), $m.Groups[2].Value.ToUpper())
	}
	return $null
}

function Derive-StateFlag
{
	param($d)
	$attached = [bool]$d.ClientIPAddress
	$bound = ( [bool]$d.PersistedGuid -or [bool]$d.IsForced )
	return [pscustomobject]@{ Bound = $bound; Attached = $attached }
}

function Get-DeviceList
{
	$raw = @(Get-DevicesRaw)
	$out = foreach ($d in $raw)
	{
		$flags = Derive-StateFlag $d
		[pscustomobject]@{
			BusId       = if ($d.BusId)
			{
				"$($d.BusId)"
			}
			else
			{
				''
			}
			Bound       = [bool]$flags.Bound
			Attached    = [bool]$flags.Attached
			VidPid      = Get-VidPid $d.InstanceId
			Description = "$($d.Description)"
		}
	}
	# Sort: Attached first, then Bound, then BusId
	$out = $out | Sort-Object @{e = { $_.Attached -as [int] } ; Descending = $true }, @{e = { $_.Bound -as [int] } ; Descending = $true }, @{e = { $_.BusId } }
	return @($out)
}

# ---------- Reattach process discovery ----------
function Get-ReattachProcess
{
	# Returns: { PID, Mode='BusId'|'HardwareId', Key, CommandLine }
	$procs = Get-CimInstance Win32_Process -Filter "Name='usbipd.exe'"
	$out = @()
	foreach ($p in $procs)
	{
		$cl = $p.CommandLine; if (-not $cl)
		{
			continue
		}
		if ($cl -notmatch 'attach' -or $cl -notmatch '--wsl' -or $cl -notmatch '--auto-attach')
		{
			continue
		}

		$mB = [regex]::Match($cl, '--busid\s+("?)([^"\s]+)\1', 'IgnoreCase')
		if ($mB.Success)
		{
			$out += [pscustomobject]@{ PID = $p.ProcessId; Mode = 'BusId'; Key = $mB.Groups[2].Value; CommandLine = $cl }
			continue
		}
		$mH = [regex]::Match($cl, '--hardware-id\s+("?)([^"\s]+)\1', 'IgnoreCase')
		if ($mH.Success)
		{
			$out += [pscustomobject]@{ PID = $p.ProcessId; Mode = 'HardwareId'; Key = $mH.Groups[2].Value.ToUpper(); CommandLine = $cl }
		}
	}
	return @($out)
}

function Stop-AllReattach
{
	[CmdletBinding(SupportsShouldProcess = $true)]
	param()
	$all = @(Get-ReattachProcess)
	foreach ($p in $all)
	{
		try
		{
			Stop-Process -Id $p.PID -Force -ErrorAction Stop
		}
		catch
		{
			Write-Verbose "Ignored: $($_.Exception.Message)"
		}
	}
}

function Stop-Reattach-ForDevice
{
	[CmdletBinding(SupportsShouldProcess = $true)]
	param([string]$BusId, [string]$VidPid)
	$procs = @(Get-ReattachProcess)
	if ($BusId)
	{
		foreach ($p in $procs | Where-Object { $_.Mode -eq 'BusId' -and $_.Key -eq $BusId })
		{
			try
			{
				Stop-Process -Id $p.PID -Force -ErrorAction Stop
			}
			catch
			{
				Write-Verbose "Ignored: $($_.Exception.Message)"
			}
		}
	}
	if ($VidPid)
	{
		$k = $VidPid.ToUpper()
		foreach ($p in $procs | Where-Object { $_.Mode -eq 'HardwareId' -and $_.Key -eq $k })
		{
			try
			{
				Stop-Process -Id $p.PID -Force -ErrorAction Stop
			}
			catch
			{
				Write-Verbose "Ignored: $($_.Exception.Message)"
			}
		}
	}
}

# ---------- Small state wait ----------
function Wait-ForState
{
	param([string]$BusId, [ValidateSet('Bound', 'Attached', 'Not shared')][string]$Desired)
	$deadline = [Environment]::TickCount + $STATE_TIMEOUT_MS
	while ([Environment]::TickCount -lt $deadline)
	{
		try
		{
			$e = @(Get-DeviceList) | Where-Object { $_.BusId -eq $BusId } | Select-Object -First 1
			if ($e)
			{
				switch ($Desired)
				{
					'Bound'
					{
						if ($e.Bound -and -not $e.Attached)
						{
							return $true
						}
					}
					'Attached'
					{
						if ($e.Attached)
						{
							return $true
						}
					}
					'Not shared'
					{
						if (-not $e.Bound -and -not $e.Attached)
						{
							return $true
						}
					}
				}
			}
		}
		catch
		{
			Write-Verbose "Ignored: $($_.Exception.Message)"
		}
		Start-Sleep -Milliseconds $STATE_POLL_MS
	}
	return $false
}

function BoolMark
{
	param([bool]$b) if ($b)
	{
		return $Check
	}
	else
	{
		return $Cross
	}
}

# ---------- Actions ----------
function Try-Bind-BusId
{
	param([string]$BusId)
	$dev = @(Get-DeviceList) | Where-Object BusId -eq $BusId | Select-Object -First 1
	if (-not $dev)
	{
		Write-Host "$Cross Unknown device." -ForegroundColor Red; return $false
	}
	if ($dev.Bound)
	{
		return $true
	}

	$r1 = Invoke-External 'usbipd' @('bind', '--busid', $BusId)
	if ($r1.ExitCode -eq 0)
	{
		[void](Wait-ForState -BusId $BusId -Desired 'Bound'); return $true
	}

	$r2 = Invoke-UsbipdElevated -UsbipdArgs @('bind', '--busid', $BusId)
	if ($r2.ExitCode -eq 0)
	{
		[void](Wait-ForState -BusId $BusId -Desired 'Bound'); return $true
	}

	Write-Host "$Cross Bind failed." -ForegroundColor Red
	return $false
}

function Attach-Once
{
	param([string]$BusId, [string]$VidPid)

	# Prefer BusId if present
	if ($BusId)
	{
		if (-not (Try-Bind-BusId $BusId))
		{
			return
		}
		$res = Invoke-External 'usbipd' @('attach', '--wsl', '--busid', $BusId)
		if ($res.ExitCode -eq 0)
		{
			[void](Wait-ForState -BusId $BusId -Desired 'Attached'); Write-Host "$Check Attached." ; return
		}
	}

	# Fallback to HardwareId
	if ($VidPid)
	{
		$res = Invoke-External 'usbipd' @('attach', '--wsl', '--hardware-id', $VidPid)
		if ($res.ExitCode -eq 0)
		{
			Write-Host "$Check Attached." ; return
		}
		$b1 = Invoke-External 'usbipd' @('bind', '--hardware-id', $VidPid)
		if ($b1.ExitCode -ne 0)
		{
			$b2 = Invoke-UsbipdElevated -UsbipdArgs @('bind', '--hardware-id', $VidPid)
			if ($b2.ExitCode -ne 0)
			{
				Write-Host "$Cross Attach failed (bind denied)." -ForegroundColor Red; return
			}
		}
		$res2 = Invoke-External 'usbipd' @('attach', '--wsl', '--hardware-id', $VidPid)
		if ($res2.ExitCode -eq 0)
		{
			Write-Host "$Check Attached."
		}
		else
		{
			Write-Host "$Cross Attach failed." -ForegroundColor Red
		}
		return
	}

	Write-Host "$Cross Cannot attach: no BusId or Hardware Id available." -ForegroundColor Red
}

function Reattach-BusId
{
	param([string]$BusId)
	if (-not (Try-Bind-BusId $BusId))
	{
		return
	}
	$active = @(Get-ReattachProcess | Where-Object { $_.Mode -eq 'BusId' -and $_.Key -eq $BusId }).Count -gt 0
	if ($active)
	{
		Write-Host 'Reattach (BusId) already active.' ; return
	}
	$p = Start-Process -FilePath 'usbipd' -ArgumentList @('attach', '--wsl', '--busid', $BusId, '--auto-attach') -WindowStyle Hidden -PassThru
	if ($p -and -not $p.HasExited)
	{
		[void](Wait-ForState -BusId $BusId -Desired 'Attached'); Write-Host "$Check Reattach (BusId) started (PID $($p.Id))."
	}
	else
	{
		Write-Host "$Cross Could not start reattach (BusId)." -ForegroundColor Red
	}
}

function Reattach-Hardware
{
	param([string]$VidPid)
	$k = $VidPid.ToUpper()
	$active = @(Get-ReattachProcess | Where-Object { $_.Mode -eq 'HardwareId' -and $_.Key -eq $k }).Count -gt 0
	if ($active)
	{
		Write-Host 'Reattach (HW) already active.' ; return
	}
	$p = Start-Process -FilePath 'usbipd' -ArgumentList @('attach', '--wsl', '--hardware-id', $VidPid, '--auto-attach') -WindowStyle Hidden -PassThru
	if ($p -and -not $p.HasExited)
	{
		Write-Host "$Check Reattach (HW) started (PID $($p.Id))."
	}
	else
	{
		Write-Host "$Cross Could not start reattach (HW)." -ForegroundColor Red
	}
}

function Detach-And-Unbind
{
	param([string]$BusId, [string]$VidPid)

	# Stop any reattach loops for this device (both keys).
	Stop-Reattach-ForDevice -BusId $BusId -VidPid $VidPid

	# DETACH (prefer BusId; fall back to HW if no BusId)
	$detached = $false
	if ($BusId)
	{
		$res = Invoke-External 'usbipd' @('detach', '--busid', $BusId)
		if ($res.ExitCode -eq 0)
		{
			$detached = $true
		}
	}
	elseif ($VidPid)
	{
		$res = Invoke-External 'usbipd' @('detach', '--hardware-id', $VidPid)
		if ($res.ExitCode -eq 0)
		{
			$detached = $true
		}
	}
	if ($detached)
	{
		Write-Host "$Check Detached."
	}
	else
	{
		Write-Host "$Cross Detach failed or not applicable." -ForegroundColor Red
	}

	# UNBIND (prefer BusId; fall back to HW). Try unelevated then elevated.
	$unbound = $false
	if ($BusId)
	{
		$u1 = Invoke-External 'usbipd' @('unbind', '--busid', $BusId)
		if ($u1.ExitCode -eq 0)
		{
			$unbound = $true
		}
		else
		{
			$u2 = Invoke-UsbipdElevated -UsbipdArgs @('unbind', '--busid', $BusId)
			if ($u2.ExitCode -eq 0)
			{
				$unbound = $true
			}
		}
	}
	elseif ($VidPid)
	{
		$u1 = Invoke-External 'usbipd' @('unbind', '--hardware-id', $VidPid)
		if ($u1.ExitCode -eq 0)
		{
			$unbound = $true
		}
		else
		{
			$u2 = Invoke-UsbipdElevated -UsbipdArgs @('unbind', '--hardware-id', $VidPid)
			if ($u2.ExitCode -eq 0)
			{
				$unbound = $true
			}
		}
	}
	if ($unbound)
	{
		Write-Host "$Check Unbound."
	}
	else
	{
		Write-Host "$Cross Unbind failed (admin may be required)." -ForegroundColor Yellow
	}
}

function Reset-All
{
	[CmdletBinding(SupportsShouldProcess = $true)]
	param()
	Write-Host 'Resetting…'
	Stop-AllReattach
	[void](Invoke-External 'usbipd' @('detach', '--all'))
	$u = Invoke-External 'usbipd' @('unbind', '--all')
	if ($u.ExitCode -ne 0)
	{
		$u2 = Invoke-UsbipdElevated -UsbipdArgs @('unbind', '--all')
		if ($u2.ExitCode -ne 0)
		{
			Write-Host 'Unbind skipped (admin required).' -ForegroundColor Yellow
		}
		else
		{
			Write-Host 'Unbound all.'
		}
	}
	else
	{
		Write-Host 'Unbound all.'
	}
	Write-Host "$Check Reset complete."
}

# ---------- Prereqs + banner ----------
function Test-Prereqs-And-Banner
{
	$psv = $PSVersionTable.PSVersion.ToString()
	$uv = Get-UsbipdVersion
	Write-Host "UsbIpdTool $script:ToolVersion"
	Write-Host "PowerShell: $psv"
	Write-Host "usbipd-win: $uv"
	Write-Host ''
	Write-Host 'Press Ctrl+C to exit.'
	Write-Host ''

	if (-not (Get-Command usbipd -ErrorAction SilentlyContinue))
	{
		Write-Host "$Cross usbipd not found (winget install dorssel.usbipd-win)." -ForegroundColor Red
		return $false
	}
	if ([version]$uv -lt [version]'5.2.0')
	{
		Write-Host "$Cross usbipd $uv detected; need >= 5.2.0." -ForegroundColor Red
		return $false
	}
	try
	{
		$null = @(Get-DeviceList)
	}
	catch
	{
		Write-Host "$Cross Could not parse 'usbipd state'." -ForegroundColor Red
		return $false
	}
	return $true
}

# ---------- UI ----------
function Show-Table
{
	$list = @(Get-DeviceList)
	$rtchs = @(Get-ReattachProcess)
	$byBus = @{}; $byHw = @{}
	foreach ($p in $rtchs)
	{
		if ($p.Mode -eq 'BusId')
		{
			$byBus[$p.Key] = $true
		}
		elseif ($p.Mode -eq 'HardwareId')
		{
			$byHw[$p.Key.ToUpper()] = $true
		}
	}

	if ($list.Count -eq 0)
	{
		Write-Host '(no devices found)'; return @()
	}

	Write-Host ('{0,2} {1,-6} {2,-5} {3,-8} {4,-16} {5,-14} {6}' -f '#', 'BusId', 'Bound', 'Attached', 'Reattach (BusId)', 'Reattach (HW)', 'Description')
	Write-Host ('{0,2} {1,-6} {2,-5} {3,-8} {4,-16} {5,-14} {6}' -f '--', '------', '-----', '--------', '----------------', '--------------', '-----------')

	for ($i = 0; $i -lt $list.Count; $i++)
	{
		$row = $list[$i]
		$busDisp = if ($row.BusId)
		{
			$row.BusId
		}
		else
		{
			'—'
		}
		$rb = if ($row.BusId -and $byBus.ContainsKey($row.BusId))
		{
			$Check
		}
		else
		{
			$Cross
		}
		$rh = if ($row.VidPid -and $byHw.ContainsKey($row.VidPid.ToUpper()))
		{
			$Check
		}
		else
		{
			$Cross
		}
		$bMk = BoolMark $row.Bound
		$aMk = BoolMark $row.Attached
		Write-Host ('{0,2} {1,-6} {2,-5} {3,-8} {4,-16} {5,-14} {6}' -f ($i + 1), $busDisp, $bMk, $aMk, $rb, $rh, $row.Description)
	}
	return $list
}

function Show-DeviceMenu
{
	param([int]$Index, [object[]]$List)

	if ($Index -lt 1 -or $Index -gt $List.Count)
	{
		Write-Host 'Out of range.'; return
	}
	$d = $List[$Index - 1]
	$bus = $d.BusId
	$vid = $d.VidPid

	$rbActive = if ($bus)
	{
		@(Get-ReattachProcess | Where-Object { $_.Mode -eq 'BusId' -and $_.Key -eq $bus }).Count -gt 0
	}
	else
	{
		$false
	}
	$rhActive = if ($vid)
	{
		@(Get-ReattachProcess | Where-Object { $_.Mode -eq 'HardwareId' -and $_.Key -eq $vid.ToUpper() }).Count -gt 0
	}
	else
	{
		$false
	}

	$busDisp = if ($bus)
	{
		$bus
	}
	else
	{
		'—'
	}
	$vidDisp = if ($vid)
	{
		$vid
	}
	else
	{
		'n/a'
	}
	$rbMark = BoolMark $rbActive
	$rhMark = BoolMark $rhActive
	$boundMk = BoolMark $d.Bound
	$attMk = BoolMark $d.Attached

	Write-Host ''
	Write-Host ('#{0}  BusId={1}  Bound={2}  Attached={3}  Reattach(BusId)={4}  Reattach(HW)={5}  HardwareId={6}' -f `
			$Index, $busDisp, $boundMk, $attMk, $rbMark, $rhMark, $vidDisp)

	$prompt = if ($vid)
	{
		' [A]ttach, [D]etach, or attach and auto-reattach by [B]usId or [H]ardwareId '
	}
	else
	{
		' [A]ttach, [D]etach, or attach and auto-reattach by [B]usId '
	}

	$choice = (Read-Host $prompt).Trim()
	switch ($choice.ToUpper())
	{
		'A'
		{
			Attach-Once -BusId $bus -VidPid $vid; return
		}
		'B'
		{
			if ($bus)
			{
				Reattach-BusId -BusId $bus
			}
			else
			{
				Write-Host 'No BusId available for this device.' -ForegroundColor Yellow
			}; return
		}
		'H'
		{
			if ($vid)
			{
				Reattach-Hardware -VidPid $vid
			}
			else
			{
				Write-Host 'No Hardware Id (VID:PID) available.' -ForegroundColor Yellow
			}; return
		}
		'D'
		{
			Detach-And-Unbind -BusId $bus -VidPid $vid; return
		}
		default
		{
			return
		}
	}
}

function Start-Loop
{
	[CmdletBinding(SupportsShouldProcess = $true)]
	param()
	if (-not (Test-Prereqs-And-Banner))
	{
		return
	}
	while ($true)
	{
		$list = Show-Table
		$prompt = if ($list.Count -gt 0)
		{
			" Select device (1-$($list.Count)) or [R]eset all "
		}
		else
		{
			' No devices. [R]eset all or Ctrl+C to exit '
		}
		$userInput = (Read-Host $prompt).Trim()
		if ($userInput -eq '')
		{
			continue
		}
		if ($userInput -match '^[Rr]$')
		{
			Reset-All; continue
		}
		if ($userInput -match '^\d+$')
		{
			$n = [int]$userInput
			if ($n -ge 1 -and $n -le $list.Count)
			{
				Show-DeviceMenu -Index $n -List $list
			}
			else
			{
				Write-Host " Please enter 1-$($list.Count) or R. "
			}
			continue
		}
		Write-Host ' Please enter a listed number, or R. '
	}
}

# ---------- Main entry ----------
# Entry (graceful Ctrl+C)
try
{
	Start-Loop
}
catch [System.OperationCanceledException]
{
	"`n"; return
}
catch [System.Management.Automation.PipelineStoppedException]
{
	"`n"; return
}
