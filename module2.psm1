function Get-HiddenFiles {
    <#
    .SYNOPSIS
    Show hidden files from a specific folder.
    
    .DESCRIPTION
    The Get-HiddenFiles function takes the path of a folder and lists all the hidden files present in it.
    If the folder does not exist, an error is thrown.

    .PARAMETER FolderPath
    Path of the folder to be scanned for hidden files.

    .EXAMPLE
    Get-HiddenFiles -FolderPath "C:\Folder"
    This example shows all the hidden files in the folder "C:\Folder".
    #>

    [CmdletBinding()]
    param (
        # Mandatory parameter that defines the path of the folder to analyze
        [Parameter(Mandatory = $true)]
        [string]$FolderPath
    )
    
    try {
        # Activate strict mode
        Set-StrictMode -Version Latest
        
        # Check if the folder specified in FolderPath exists
        if (-not (Test-Path -Path $FolderPath)) {
            throw "La carpeta no existe: $FolderPath"  # Throw exception if folder does not exist
        }

        # Get and list hidden files in the specified folder
        Get-ChildItem -Path $FolderPath -Hidden -File
    }
    catch {
        # Handle errors and display a message in case of failure
        Write-Error "Error al listar archivos ocultos: $_"
    }
}
