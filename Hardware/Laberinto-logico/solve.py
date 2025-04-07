# --- START OF FILE solve_bruteforce.py ---

import csv
import sys
import itertools

def apply_brute_force_logic(a_str, b_str, c_str, d_str, function_id):
  """
  Aplica una función lógica arbitraria de 4 entradas basada en su ID.
  El ID (0 a 65535) representa la tabla de verdad de la función.
  """
  # Convertir entradas a un índice (0-15)
  # El orden A, B, C, D corresponde a los bits más a menos significativos
  # para formar el índice. '1111' -> 15, '0000' -> 0
  try:
    input_index = int(a_str + b_str + c_str + d_str, 2)
  except ValueError:
      # Esto no debería ocurrir si la validación previa funciona
      print(f"Error interno: Valor no binario pasado a apply_brute_force_logic: {a_str}{b_str}{c_str}{d_str}", file=sys.stderr)
      return 0 # Devuelve un valor por defecto

  # Obtener el bit de salida correspondiente de la function_id
  # El bit 'input_index'-ésimo de function_id determina la salida
  # para esa combinación de entrada.
  # (function_id >> input_index) desplaza el bit deseado a la posición 0
  # & 1 aísla ese bit.
  output_bit = (function_id >> input_index) & 1
  
  return output_bit

def decode_bits_to_ascii(bits_string):
  """
  Convierte una cadena de bits en caracteres ASCII.
  Maneja posibles errores. Retorna None si hay error crítico.
  """
  if not bits_string:
      return ""
      
  ascii_string = ""
  length = len(bits_string)
  usable_length = length - (length % 8)

  # No imprimimos warnings aquí para no llenar la salida durante el brute force
  # if length % 8 != 0:
  #     print(f"Warning: Total bits ({length}) no es múltiplo de 8. Ignorando los últimos {length % 8} bits.", file=sys.stderr)

  if usable_length == 0 and length > 0:
      # No hay suficientes bits para formar un byte completo
      return None 

  for i in range(0, usable_length, 8):
      byte = bits_string[i:i+8]
      try:
          char_code = int(byte, 2)
          # Añadimos una comprobación para asegurarnos de que es ASCII imprimible o común
          # si queremos filtrar más, pero para la flag, cualquier byte es posible.
          # if 32 <= char_code <= 126 or char_code in [9, 10, 13]: # Rango imprimible + TAB, LF, CR
          ascii_string += chr(char_code)
          # else:
          #     # Carácter no imprimible encontrado, podría no ser texto legible
          #     return None # O manejarlo de otra forma si queremos permitir binario
      except ValueError:
          # print(f"Error: No se pudo convertir el byte '{byte}' a entero.", file=sys.stderr)
          return None # Indica un error en la decodificación
      except OverflowError:
          # print(f"Error: El valor del byte '{byte}' ({char_code}) es demasiado grande para chr().", file=sys.stderr)
          # Esto no debería ocurrir con bytes de 8 bits
           return None
      except Exception as e:
          # print(f"Error desconocido al procesar byte '{byte}': {e}", file=sys.stderr)
          return None

  return ascii_string

def main():
  """
  Función principal para leer CSV, aplicar TODAS las lógicas posibles y decodificar,
  buscando la flag.
  """
  input_filename = 'inputs.csv'
  input_data = []
  line_num = 0

  # --- 1. Leer y validar los datos de entrada UNA VEZ ---
  try:
    with open(input_filename, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        
        try:
            header = next(reader)
            line_num += 1
            # Es útil saber si la cabecera es rara, pero no crítico para el brute force
            # if header != ['A', 'B', 'C', 'D']:
            #      print(f"Warning: Cabecera inesperada: {header}", file=sys.stderr)

        except StopIteration:
            print(f"Error: El archivo CSV '{input_filename}' está vacío o no tiene cabecera.", file=sys.stderr)
            return

        for row in reader:
            line_num += 1
            if len(row) == 4:
                a, b, c, d = row
                if all(val in ('0', '1') for val in [a, b, c, d]):
                    input_data.append((a, b, c, d)) # Guardar como tupla
                else:
                    print(f"Warning: Fila {line_num} contiene valores no binarios: {row}. Saltando.", file=sys.stderr)
                    # Podríamos parar si los datos son malos, pero intentemos continuar
            elif row: 
                print(f"Warning: Fila {line_num} no tiene 4 columnas: {row}. Saltando.", file=sys.stderr)

  except FileNotFoundError:
      print(f"Error: No se encontró el archivo '{input_filename}'", file=sys.stderr)
      return
  except Exception as e:
      print(f"Error al leer el archivo CSV: {e}", file=sys.stderr)
      return

  if not input_data:
      print("Error: No se leyeron datos válidos del CSV.", file=sys.stderr)
      return
      
  print(f"Se leyeron {len(input_data)} filas de entrada válidas.")
  print("Iniciando búsqueda por fuerza bruta de la función lógica (0 a 65535)...")

  found = False
  # --- 2. Iterar por todas las posibles funciones lógicas ---
  for func_id in range(65536): # 0 to 65535 (2^16 - 1)
      
      # Imprimir progreso cada cierto número de intentos
      if func_id % 4096 == 0:
          print(f"Probando función ID: {func_id}...", file=sys.stderr)

      output_bits = ""
      # --- 3. Generar la secuencia de bits para la función actual ---
      for a, b, c, d in input_data:
          output_bit = apply_brute_force_logic(a, b, c, d, func_id)
          output_bits += str(output_bit)

      # --- 4. Decodificar la secuencia de bits ---
      if len(output_bits) >= 8: # Necesitamos al menos 8 bits para un carácter
          decoded_string = decode_bits_to_ascii(output_bits)
          
          # --- 5. Comprobar si la cadena decodificada contiene la subcadena buscada ---
          if decoded_string is not None and "hfctf" in decoded_string:
              print(f"\n--- ¡Posible Coincidencia Encontrada! ---")
              print(f"Función Lógica ID: {func_id} (Decimal) / {func_id:04X} (Hex) / {func_id:016b} (Binario - Tabla Verdad)")
              print(f"Bits Generados ({len(output_bits)}): {output_bits[:80]}{'...' if len(output_bits)>80 else ''}") # Mostrar solo una parte
              # Usar repr() para ver caracteres no imprimibles claramente
              print(f"Resultado Decodificado (repr): {repr(decoded_string)}") 
              print(f"Resultado Decodificado (directo): {decoded_string}")
              print(f"----------------------------------------")
              found = True
              # Descomenta la siguiente línea si quieres parar tras la primera coincidencia
              # break 

  if not found:
      print("\nBúsqueda completada. No se encontró ninguna función que produzca 'hfctf' en la salida decodificada.")
  else:
      print("\nBúsqueda completada.")


if __name__ == "__main__":
  main()

# --- END OF FILE solve_bruteforce.py ---
