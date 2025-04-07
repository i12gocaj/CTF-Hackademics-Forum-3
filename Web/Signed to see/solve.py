#!/usr/bin/env python3

import requests
import binascii
try:
    # Intenta importar la biblioteca hashpumpy
    import hashpumpy
except ImportError:
    print("Error: La biblioteca 'hashpumpy' no está instalada o no se pudo importar.")
    print("Asegúrate de haberla instalado (pip install hashpumpy)")
    print("y que la biblioteca C subyacente 'libhashpump' esté disponible si es necesario.")
    exit(1)

# --- Configuración ---
# Asegúrate de cambiar esta URL a la correcta del reto CTF
url = "http://ctf.hackademics-forum.com:33819/"
known_hash = "c9d4b01ce16b640782af2864a47547d88fc02cab" # La firma SHA1 de SECRET + 'test.txt'
known_data_str = "test.txt"       # Los datos originales (como string)
data_to_append_str = "flag.txt"   # Los datos que queremos añadir (como string)
max_key_length_to_try = 64        # Rango máximo de longitud de clave secreta a probar
# ---------------------

print(f"Target URL: {url}")
print(f"Known Hash (for '{known_data_str}'): {known_hash}")
print(f"Appending Data: '{data_to_append_str}'")
print("-" * 30)

found = False
for key_length in range(1, max_key_length_to_try + 1):
    print(f"[*] Trying key length: {key_length}...")
    try:
        # Calcula la nueva firma y el nuevo mensaje usando hashpumpy
        # Parámetros: (hash_conocido_hex, datos_conocidos_str, datos_a_añadir_str, longitud_clave)
        new_hash, new_message_bytes = hashpumpy.hashpump(known_hash, known_data_str, data_to_append_str, key_length)

        # new_message_bytes ya está en formato bytes (incluyendo el padding)

        # Prepara los datos para la petición POST
        post_key = new_hash
        post_file_hex = binascii.hexlify(new_message_bytes).decode('ascii')

        # Crea el payload para la petición POST
        payload = {
            'file': post_file_hex,
            'key': post_key
        }

        # Envía la petición POST
        response = requests.post(url, data=payload, timeout=10)

        # Comprueba si la respuesta NO contiene el mensaje de error
        if "Invalid file or signature!" not in response.text:
            print("\n[+] SUCCESS!")
            print(f"[+] Found potential key length: {key_length}")
            print(f"[+] Generated Hash (key): {post_key}")
            # print(f"[+] Generated Message Hex (file): {post_file_hex}") # Descomentar si quieres verlo
            print("-" * 30)
            print("Response Content (Flag?):")
            print(response.text)
            print("-" * 30)
            found = True
            break # Sal del bucle si se encontró la flag

    except Exception as e:
        # hashpumpy puede lanzar excepciones específicas o genéricas
        print(f"[!] Error occurred for key length {key_length}: {e}")
        # Si el error es por la biblioteca C, puede que necesites instalar libhashpump-dev

if not found:
    print(f"\n[-] Failed to find the flag after trying key lengths up to {max_key_length_to_try}.")
