function Get-SuspiciousProcesses {
    <#
    .SYNOPSIS
    Look for suspicious processes based on high CPU usage or names associated with malware.
    
    .PARAMETER CpuThreshold
    The CPU threshold that considers a process suspicious (in percentage).

    .PARAMETER KnownBadProcessNames
    List of names of known or suspected malicious processes.

    .EXAMPLE
    Get-SuspiciousProcesses -CpuThreshold 50 -KnownBadProcessNames @("badprocess.exe", "malware.exe")
    
    .DESCRIPTION
    Checks running processes and alerts if they exceed a certain CPU threshold or if their names match known malicious processes.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$CpuThreshold,

        [Parameter(Mandatory = $false)]
        [string[]]$KnownBadProcessNames = @("badprocess.exe", "malware.exe", "suspicious.exe")
    )
    
    try {
        # Activate strict mode
        Set-StrictMode -Version Latest

        # Get all running processes
        $processes = Get-Process

        # Check processes with high CPU usage
        $highCpuProcesses = $processes | Where-Object { $_.CPU -gt $CpuThreshold }

        if ($highCpuProcesses) {
            Write-Host "Procesos que utilizan m s de $CpuThreshold% CPU:"
            $highCpuProcesses | ForEach-Object {
                try {
                    Write-Host "$($.Name) - CPU: $($.CPU)"
                }
                catch {
                    Write-Error "Error al recuperar la informaci n del proceso: $_"
                }
            }
        } else {
            Write-Host "Ning n proceso excede $CpuThreshold% CPU."
        }

        # Search for known malicious processes
        $badProcesses = $processes | Where-Object {
            try {
                $KnownBadProcessNames -contains $_.Name
            }
            catch {
                Write-Error "Ning n proceso excede: $_"
            }
        }

        if ($badProcesses) {
            Write-Host "Procesos sospechosos conocidos en ejecuci n:"
            $badProcesses | ForEach-Object {
                try {
                    Write-Host "$($_.Name) est  corriendo. Considere investigar."
                }
                catch {
                    Write-Error "Error al recuperar informaci n de proceso sospechoso: $_"
                }
            }
        } else {
            Write-Host "No se est n ejecutando procesos sospechosos conocidos."
        }
    }
    catch {
        Write-Error "Error al buscar procesos sospechosos: $_"
    }
}

# Export function
Export-ModuleMember -Function Get-SuspiciousProcesses
                    Write-Error "Error retrieving suspicious process information: $_"
                }
            }
        } else {
            Write-Host "No known suspicious processes are running."
        }
    }
    catch {
        Write-Error "Error al buscar procesos sospechosos: $_"
    }
}

# Exportar la funci n
Export-ModuleMember -Function Get-SuspiciousProcesses
