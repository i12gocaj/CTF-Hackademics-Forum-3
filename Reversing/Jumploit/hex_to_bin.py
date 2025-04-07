import sys
import binascii # Usaremos binascii para una conversión robusta

INPUT_HEX_FILE = 'flag_data_hex.txt'
OUTPUT_BIN_FILE = 'flag_data.bin'

try:
    # 1. Leer el contenido del archivo de texto hexadecimal
    print(f"Leyendo '{INPUT_HEX_FILE}'...")
    with open(INPUT_HEX_FILE, 'r') as f:
        hex_string = f.read()
    print(f"  Leídos {len(hex_string)} caracteres.")

    # 2. Limpiar la cadena hexadecimal (eliminar espacios, saltos de línea, etc.)
    cleaned_hex = "".join(hex_string.split())
    print(f"  Cadena hexadecimal limpiada (longitud {len(cleaned_hex)}).")

    # 3. Validar que la longitud sea par (cada byte son 2 caracteres hex)
    if len(cleaned_hex) % 2 != 0:
        print("Error: La cadena hexadecimal tiene una longitud impar después de limpiarla.")
        print("Asegúrate de que el archivo contenga una secuencia válida de pares hexadecimales.")
        sys.exit(1)

    # 4. Convertir la cadena hexadecimal a bytes crudos
    print("Convirtiendo hexadecimal a bytes...")
    try:
        raw_bytes = binascii.unhexlify(cleaned_hex)
    except binascii.Error as e:
        print(f"Error durante la conversión hexadecimal: {e}")
        print("Asegúrate de que el archivo contenga solo caracteres hexadecimales válidos (0-9, a-f, A-F).")
        sys.exit(1)
    print(f"  Conversión exitosa a {len(raw_bytes)} bytes.")

    # 5. Escribir los bytes crudos al archivo binario de salida
    print(f"Escribiendo bytes en '{OUTPUT_BIN_FILE}'...")
    with open(OUTPUT_BIN_FILE, 'wb') as f:
        f.write(raw_bytes)
    print("¡Archivo binario creado exitosamente!")

except FileNotFoundError:
    print(f"Error: No se encontró el archivo de entrada '{INPUT_HEX_FILE}'.")
    print("Asegúrate de que el archivo exista en el mismo directorio que este script.")
    sys.exit(1)
except Exception as e:
    print(f"Ocurrió un error inesperado: {e}")
    sys.exit(1)
