function Get-SystemResourceUsage {
    <#
    .SYNOPSIS
    Displays the system usage: CPU (porcentage), Memory, Disk and Red.

    .DESCRIPTION
    Gets and displays the current system CPU, memory, disk, and network adapter usage.
    
    .EXAMPLE
    Get-SystemResourceUsage
    #>
    
    try {
        Set-StrictMode -Version Latest
        
        # CIP
        $cpu = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object Average
        
        # Memory
        $memory = Get-WmiObject Win32_OperatingSystem
        $totalMemory = [math]::Round($memory.TotalVisibleMemorySize/1MB,2)
        $freeMemory = [math]::Round($memory.FreePhysicalMemory/1MB,2)
        $usedMemory = $totalMemory - $freeMemory
        
        # Disk
        $disk = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3"
        
        # Red
        $network = Get-NetAdapter | Select-Object Name, Status, LinkSpeed
        
        [PSCustomObject]@{
            CPU_Usage = "$($cpu.Average)%"
            Memory_Usage = "$usedMemory MB de $totalMemory MB"
            Disk_Usage = $disk | Select-Object DeviceID, Size, FreeSpace
            Network_Adapters = $network
        }
    }
    catch {
        Write-Error "Error al obtener el uso de recursos del sistema: $_"
    }
}
