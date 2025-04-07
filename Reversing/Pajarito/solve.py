import sys

# La cadena que nos dio el pajarito (la salida del programa)
encoded_reversed_string = "431 510 670 730 430 140 070 450 410 520 640 450 310 740 640 500 270 760 601 370 320 140 550 260 700 450 370 530 370 611 350 450 150 350 540 070 310 370 660 300 010 340 360 760 510 640 140 250 250 060 350 230 710 201 070 760 521 760 640 600 700 750 540 000 110 450 750 370 220 721 650 000 120 230 070 040 700 140 000 200 500 230 660 060 210 101 330 200 200 750 040 370 410 170 670 600 600 231 050 330 610 240 250 500 500 070 660 600 520 770 121 300 130 340 460 550 300 570 160 500 220 440 531 340 500 570 540 050 720 370 150 350 420 360 540 370 110 440 060 050 001 621 400 000 600 760 050 530 610 240 270 500 230 750 030 100 500 760 270 370 420 340 440 370 401 150 140 550 720 050 760 340 130 140 560 200 500 230 010 000 100 130 710 070 110 131 230 200 501 231 670 670 021 450 200 330 500 560 670 370 620 750 010 000 100 130 710 070 230 740 060 500 220 721 670 100 600 520 450 340 500 540 631 200 321 750 260 370 420 740 410 300 200 760 401 070 000 170 650 550 510 450 740 060 230 160 250 500 500 070 660 600 520 760 160 070 530 031 060 000"
key = "awanabumbambamwiyobadiou"
key_len = len(key)

# Paso 1: Revertir la inversión de la *cadena completa*
encoded_string_unreversed = encoded_reversed_string[::-1]

# Paso 2: Dividir la cadena (ya revertida) por los espacios para obtener la lista de números octales.
# Usamos strip() para eliminar espacios en blanco al principio/final que puedan resultar de la inversión.
encoded_octal_list = encoded_string_unreversed.strip().split()

# Paso 3: Decodificar el XOR
decoded_chars = []
for i, octal_str in enumerate(encoded_octal_list):
    try:
        # Convertir la cadena octal a un entero (byte)
        xor_result_byte = int(octal_str, 8)

        # Obtener el byte de la clave correspondiente
        key_byte = ord(key[i % key_len])

        # Realizar XOR para obtener el byte original
        original_byte = xor_result_byte ^ key_byte

        # Convertir el byte original a caracter
        decoded_chars.append(chr(original_byte))
    except ValueError:
        print(f"Error: La cadena '{octal_str}' en el índice {i} no es un número octal válido.")
        sys.exit(1)
    except Exception as e:
        print(f"Error inesperado procesando '{octal_str}' en índice {i}: {e}")
        sys.exit(1)

# Unir los caracteres para obtener la flag
flag = "".join(decoded_chars)

print("La flag es:")
print(flag)
