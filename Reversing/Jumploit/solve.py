import struct
import sys

# Dimensiones de la imagen de la flag
IMG_WIDTH = 124
IMG_HEIGHT = 6
DATA_SIZE = 2976 # IMG_WIDTH * IMG_HEIGHT * 4 bytes por int

# Caracteres para dibujar (puedes cambiarlos)
PIXEL_ON = '#'
PIXEL_OFF = ' '

INPUT_FILE = 'flag_data.bin' # Nombre del archivo con los bytes extraídos

try:
    with open(INPUT_FILE, 'rb') as f:
        data = f.read()
        if len(data) != DATA_SIZE:
            print(f"Error: El archivo '{INPUT_FILE}' tiene {len(data)} bytes, se esperaban {DATA_SIZE}.")
            sys.exit(1)

        print(f"Interpretando {DATA_SIZE} bytes como una imagen de {IMG_WIDTH}x{IMG_HEIGHT}...")
        print("-" * IMG_WIDTH) # Separador superior

        # Lee los datos como enteros de 4 bytes, little-endian
        # '<' = little-endian, 'i' = signed int (podría ser 'I' unsigned)
        integers = struct.unpack(f'<{IMG_WIDTH * IMG_HEIGHT}i', data)

        # Itera por filas y columnas para "dibujar"
        idx = 0
        for y in range(IMG_HEIGHT):
            line = ""
            for x in range(IMG_WIDTH):
                # El código del juego comprueba si el valor es 1
                if integers[idx] == 1:
                    line += PIXEL_ON
                else:
                    line += PIXEL_OFF
                idx += 1
            print(line) # Imprime la línea/fila actual

        print("-" * IMG_WIDTH) # Separador inferior

except FileNotFoundError:
    print(f"Error: No se encontró el archivo '{INPUT_FILE}'. Asegúrate de haber extraído los datos.")
except Exception as e:
    print(f"Ocurrió un error: {e}")
