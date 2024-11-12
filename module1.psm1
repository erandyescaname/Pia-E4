function Get-FileHashAndCheckVirusTotal {
    <#
    .SYNOPSIS
    Obtiene el hash de un archivo y lo consulta en la API de VirusTotal.
    
    .PARAMETER FilePath
    Ruta completa del archivo a verificar.

    .EXAMPLE
    Get-FileHashAndCheckVirusTotal -FilePath "C:\archivo.exe"
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        # Modo estricto
        Set-StrictMode -Version Latest
        
        # Verificar si el archivo existe
        if (-not (Test-Path -Path $FilePath)) {
            throw "El archivo no existe: $FilePath"
        }
        
        # Obtener hash del archivo
        $fileHash = Get-FileHash -Path $FilePath -Algorithm SHA256
        
        # Consultar VirusTotal (reemplazar 'API_KEY' por la clave de VirusTotal)
        $apiKey = "776c91a8ce50fae44dec156bfe4012be639c09e15eed0fce70a945c57c74db26"
        $url = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$($fileHash.Hash)"
        
        $response = Invoke-RestMethod -Uri $url -Method Get
        $response
    }
    catch {
        Write-Error "Error al procesar el archivo: $_"
    }
}
