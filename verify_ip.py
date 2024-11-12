import argparse
import requests
import logging
import hashlib
import os
import csv
from datetime import datetime

# Ruta donde se guardarán los reportes
REPORTS_DIR = "reportes"

# Crear el directorio de reportes si no existe
os.makedirs(REPORTS_DIR, exist_ok=True)

# Función para obtener la ruta del directorio de reportes
def get_report_directory():
    """Retorna la ruta del directorio donde se guardan los reportes."""
    return os.path.abspath(REPORTS_DIR)

# Función para generar el reporte
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
    print(f"El archivo se guardó en el directorio: {get_report_directory()}")  # Mostrar directorio
    
    return report_path, hash_sha256.hexdigest()

# Función para verificar una IP
def verify_ip(ip):
    """Verifica una IP en un servicio como Shodan."""
    # Simulamos una verificación en un servicio externo (por ejemplo, Shodan)
    # Esto solo es un ejemplo, asegúrate de tener la API correspondiente para tu caso.
    response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key=TU_API_KEY")
    data = response.json()
    
    # Procesar la información para el reporte
    content = [["IP", "Pais", "Organización", "Estado"]]
    content.append([data.get("ip_str", ""), data.get("country_name", ""), data.get("org", ""), data.get("hostnames", "")])
    
    # Generar el reporte
    return generate_report(content, "Verify_IP")

# Configuración del parser de argparse
def main():
    parser = argparse.ArgumentParser(description="Verificar IP usando un servicio externo (por ejemplo, Shodan)")
    parser.add_argument("ip", type=str, help="Dirección IP a verificar")
    
    args = parser.parse_args()

    # Llamar la función de verificación de IP
    verify_ip(args.ip)

if __name__ == "__main__":
    main()