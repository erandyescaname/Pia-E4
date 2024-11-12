import os
import logging
from PIL import Image
from PIL.ExifTags import TAGS

# Configure logging
logging.basicConfig(
    filename='image_metadata.log', 
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def extract_image_metadata(image_path):
    """Extracts metadata from a given image"""
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        
        metadata = {}
        if exif_data is not None:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                metadata[tag] = value
            return metadata
        else:
            return None
    except Exception as e:
        logging.error(f"ERROR al extraer metadatos: {e}")
        return None

def main(image_path):
    """Main function for extracting image metadata"""
    if os.path.isfile(image_path):
        metadata = extract_image_metadata(image_path)
        if metadata:
            logging.info(f"Metadatos encontrados en la imagen: {image_path}")
            print("====EXIF encontrados====")
            for key, value in metadata.items():
                print(f"{key}: {value}")
        else:
            logging.info(f"NO se encontraron metadatos EXIF: {image_path}")
            print("====No se encontraron metadatos EXIF====")
    else:
        logging.error(f"La ruta indicada no es un archivo válido: {image_path}")
        print("La ruta indicada no es un archivo válido.")
