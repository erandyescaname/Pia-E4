import os
import hashlib
import logging

# Registry settings (logging)
logging.basicConfig(
    filename='ransomware_analyzer.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Common file extensions that are often targeted by ransomware
COMMON_FILE_EXTENSIONS = {'.txt', '.pdf', '.doc', '.docx', '.jpg', '.png', '.xls', '.xlsx'}

# List of common ransom note file names
RANSOM_NOTE_NAMES = {'README.txt', 'DECRYPT.txt', 'HELP_DECRYPT.txt', 'INSTRUCTIONS.txt'}


def calculate_file_hash(file_path):
    """
    Calculates the SHA-256 hash of a given file to detect changes in its content.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The SHA-256 hash of the file, or None if the file cannot be read.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                sha256_hash.update(byte_block)
        logging.info(f"Hash calculado para el archivo: {file_path}")
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        logging.error(f"Archivo no encontrado: {file_path}")
        return None
    except IOError as e:
        logging.error(f"Error al leer el archivo {file_path}: {e}")
        return None


def validate_directory(directory):
    """
    Validates if the provided directory exists and is accessible.

    Args:
        directory (str): Path to the directory.

    Returns:
        bool: True if the directory exists and is accessible, False otherwise.
    """
    if not os.path.isdir(directory):
        logging.error(f"Directorio inválido: {directory}")
        return False
    logging.info(f"Directorio válido: {directory}")
    return True


def detect_ransomware_activity(directory):
    """
    Analyzes a directory to detect suspicious ransomware-related activities.
    Detects:
    - Files with unusual extensions.
    - Possible ransom notes.

    Args:
        directory (str): Path to the directory to analyze.
    """
    try:
        suspicious_files = []
        encrypted_files = []
        ransom_notes = []

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_extension = os.path.splitext(file)[1].lower()

                # Ransom note detection
                if file in RANSOM_NOTE_NAMES:
                    ransom_notes.append(file_path)

                # Detection of files with changed extensions
                elif file_extension not in COMMON_FILE_EXTENSIONS and len(file_extension) > 0:
                    encrypted_files.append(file_path)

                # Check if the file has suspicious names
                if file_extension == '' or len(file_extension) > 6:
                    suspicious_files.append(file_path)

        # Report suspicious files
        if ransom_notes:
            print("\n[!] Se encontraron posibles notas de rescate:")
            for note in ransom_notes:
                print(f"  - {note}")
                logging.warning(f"Nota de rescate detectada: {note}")

        if encrypted_files:
            print("\n[!] Se encontraron archivos con extensiones inusuales (posibles archivos cifrados):")
            for encrypted_file in encrypted_files:
                print(f"  - {encrypted_file}")
                logging.warning(f"Archivo cifrado detectado: {encrypted_file}")

        if suspicious_files:
            print("\n[!] Se encontraron archivos con nombres o extensiones sospechosas:")
            for suspicious_file in suspicious_files:
                print(f"  - {suspicious_file}")
                logging.warning(f"Archivo sospechoso detectado: {suspicious_file}")
        else:
            print("\nNo se encontraron actividades sospechosas relacionadas con ransomware.")
            logging.info("No se encontraron actividades sospechosas relacionadas con ransomware.")

    except Exception as e:
        logging.error(f"Error al analizar el directorio: {e}")
        print(f"Error al analizar el directorio: {e}")


def main():
    """
    Main function that requests the directory to analyze and checks for suspicious activity.
    """
    try:
        # Asks the user for the directory path to analyze
        directory = input("Introduce la ruta del directorio a analizar: ")

        # Validate if the directory is valid
        if not validate_directory(directory):
            print(f"Error: El directorio '{directory}' no es válido o no existe.")
            return

        # Run the ransomware scan
        detect_ransomware_activity(directory)

    except Exception as e:
        logging.critical(f"Error en la función principal: {e}")
        print(f"Error inesperado: {e}")


if __name__ == "__main__":
    main()
