import subprocess
import argparse
import hashlib
import os
import csv
from datetime import datetime
import platform
from metadata_extraction import extract_and_log_metadata
from verify_ip import verify_ip


# Ruta donde se guardarán los reportes
REPORTS_DIR = "reportes"

# Detectar el sistema operativo actual
current_os = platform.system()
is_windows = current_os == "Windows"
is_linux = current_os == "Linux"
is_mac = current_os == "Darwin"

# Mensaje inicial sobre compatibilidad
print(f"Detectando sistema operativo: {current_os}")
if is_windows:
    print("Este script es totalmente compatible con PowerShell y Python. Bash podría no estar disponible de forma nativa.")
elif is_linux:
    print("Este script es compatible con Python y Bash. PowerShell podría no estar instalado de forma nativa.")
elif is_mac:
    print("Este script es compatible con Python y Bash. PowerShell podría necesitar instalación adicional.")
else:
    print("Advertencia: Sistema operativo desconocido. Es posible que algunos módulos o scripts no sean compatibles.")

# Crear el directorio de reportes si no existe
os.makedirs(REPORTS_DIR, exist_ok=True)

#Scripts PowerShell
def generate_report(content, task_name):
    """Genera un reporte en formato CSV y retorna el nombre y hash del archivo."""
    # Nombre del archivo basado en la fecha y la tarea
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{task_name}_{date_str}.csv"
    report_path = os.path.join(REPORTS_DIR, report_filename)
    
    # Escribir el contenido en el archivo CSV
    with open(report_path, mode="w", newline="") as file:
        writer = csv.writer(file)
        for row in content:
            writer.writerow(row)
    
    # Calcular el hash SHA256 del archivo para validación
    hash_sha256 = hashlib.sha256()
    with open(report_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    
    # Mostrar en terminal los detalles del reporte generado
    print(f"Tarea '{task_name}' ejecutada el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Reporte generado: {report_path}")
    print(f"Hash SHA256 del reporte: {hash_sha256.hexdigest()}")
    
    return report_path, hash_sha256.hexdigest()

def check_file_with_virustotal(file_path):
    # Ruta al módulo de PowerShell (ajusta esta ruta según la ubicación del módulo)
    module_path = "C:\\Program Files\\WindowsPowerShell\\Modules\\module1"

    # Comando de PowerShell para ajustar PSModulePath y ejecutar el módulo
    powershell_command = f"""
    $env:PSModulePath = '{module_path};' + $env:PSModulePath;
    Import-Module VirusTotalModule -ErrorAction SilentlyContinue;
    Get-FileHashAndCheckVirusTotal -FilePath '{file_path}'
    """

    # Ejecuta el comando de PowerShell
    result = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True, text=True)

    # Procesar salida y generar reporte
    content = [["Resource", "Response Code", "Verbose Message"]]
    content.extend([line.split() for line in result.stdout.splitlines()])
    return generate_report(content, "VirusTotal_Check")

def get_hidden_files(folder_path):
    module_path = "C:\\Program Files\\WindowsPowerShell\\Modules\\module2"
    powershell_command = f"""
    $env:PSModulePath = '{module_path};' + $env:PSModulePath;
    Import-Module HiddenFilesModule -ErrorAction SilentlyContinue;
    Get-HiddenFiles -FolderPath '{folder_path}'
    """
    result = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True, text=True)
    # Procesar salida y generar reporte
    content = [["Nombre", "Tamaño", "Fecha de Modificación"]]
    content.extend([line.split() for line in result.stdout.splitlines()])
    return generate_report(content, "Hidden_Files")

def get_system_resource_usage():
    module_path = "C:\\Program Files\\WindowsPowerShell\\Modules\\module3"
    powershell_command = f"""
    $env:PSModulePath = '{module_path};' + $env:PSModulePath;
    Import-Module SystemResourceUsageModule -ErrorAction SilentlyContinue;
    Get-SystemResourceUsage
    """
    result = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True, text=True)
    # Procesar salida y generar reporte
    content = [["Recurso", "Uso"]]
    content.extend([line.split(":") for line in result.stdout.splitlines()])
    return generate_report(content, "System_Resource_Usage")

def get_suspicious_processes(cpu_threshold, known_bad_process_names):
    module_path = "C:\\Program Files\\WindowsPowerShell\\Modules\\module4"
    process_names_str = ",".join([f"'{name}'" for name in known_bad_process_names])  # Convierte la lista a formato PS
    powershell_command = f"""
    $env:PSModulePath = '{module_path};' + $env:PSModulePath;
    Import-Module SuspiciousProcessesModule -ErrorAction SilentlyContinue;
    Get-SuspiciousProcesses -CpuThreshold {cpu_threshold} -KnownBadProcessNames @({process_names_str})
    """
    result = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True, text=True)
    # Procesar salida y generar reporte
    content = [["Proceso", "CPU%"]]
    content.extend([line.split() for line in result.stdout.splitlines()])
    return generate_report(content, "Suspicious_Processes")

#Scripts Python
#Verify IP
def verify_ip_and_report(ip):
    is_valid = verify_ip(ip)
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"verify_ip_{date_str}.txt"
    report_path = os.path.join(REPORTS_DIR, report_filename)

    with open(report_path, 'w') as report_file:
        report_file.write(f"Verificación de IP: {ip}\n")
        report_file.write(f"Resultado: {'IP válida' if is_valid else 'IP no válida'}\n")

    hash_sha256 = hashlib.sha256()
    with open(report_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)

    print(f"Tarea 'Verificación de IP' ejecutada el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Reporte generado: {report_path}")
    print(f"Hash SHA256 del reporte: {hash_sha256.hexdigest()}")

    return report_path, hash_sha256.hexdigest()

#Extraer metadatos para imagenes
def handle_image_metadata(image_path):
    print(f"Ejecutando tarea de metadatos de imagen en {image_path}")
    extract_and_log_metadata(image_path)
                             
# Menú de opciones
def main():
    parser = argparse.ArgumentParser(
        description="Ejecuta módulos de PowerShell, Python y Bash desde un script principal y genera reportes",
        epilog="""
Ejemplos de uso:
  Scripts PowerShell
  python script.py virustotal "C:\\ruta\\al\\archivo.exe"
  python script.py hiddenfiles "C:\\ruta\\de\\la\\carpeta"
  python script.py sysresource
  python script.py suspiciousproc 50 badprocess.exe malware.exe
  
  Scripts Python
  python script.py metadata "C:\\ruta\\a\\imagen.jpg
  python script.py verifyip "192.168.1.1"
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Sub-comando a ejecutar")

    # Subcomando para VirusTotalModule
    parser_virustotal = subparsers.add_parser("virustotal", help="Verifica un archivo en VirusTotal")
    parser_virustotal.add_argument("file_path", type=str, help="Ruta completa del archivo a verificar")
    
    # Subcomando para HiddenFiles
    parser_hidden_files = subparsers.add_parser("hiddenfiles", help="Lista archivos ocultos en una carpeta")
    parser_hidden_files.add_argument("folder_path", type=str, help="Ruta completa de la carpeta a analizar")

    # Subcomando para SystemResourceUsage
    parser_sys_resource = subparsers.add_parser("sysresource", help="Muestra el uso de recursos del sistema")
    
    # Subcomando para SuspiciousProcesses
    parser_suspicious_proc = subparsers.add_parser("suspiciousproc", help="Busca procesos sospechosos")
    parser_suspicious_proc.add_argument("cpu_threshold", type=int, help="Umbral de CPU para considerar procesos sospechosos (en %)")
    parser_suspicious_proc.add_argument("known_bad_process_names", nargs='+', help="Nombres de procesos sospechosos conocidos, separados por espacios")

    #Subcomando para  metadatos de imagenes
    parser_metadata = subparsers.add_parser("metadata", help="Extrae metadatos EXIF de una imagen")
    parser_metadata.add_argument("image_path", type=str, help="Ruta completa de la imagen para extraer los metadatos")
    
    # Subcomando para verificar la IP
    parser_verify_ip = subparsers.add_parser("verifyip", help="Verifica si una dirección IP es válida")
    parser_verify_ip.add_argument("ip", type=str, help="Dirección IP a verificar")

    # Parsear los argumentos
    args = parser.parse_args()

    # Ejecutar función basada en el comando seleccionado
    if args.command == "virustotal":
        check_file_with_virustotal(args.file_path)
    elif args.command == "hiddenfiles":
        get_hidden_files(args.folder_path)
    elif args.command == "sysresource":
        get_system_resource_usage()
    elif args.command == "suspiciousproc":
        get_suspicious_processes(args.cpu_threshold, args.known_bad_process_names)
    elif args.command == "metadata":
        handle_image_metadata(args.image_path)
    elif args.command == "verifyip":
        verify_ip(args.ip)

# Ejecutar el programa principal
if _name_ == "_main_":
    main()
