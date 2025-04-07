#!/usr/bin/env python3

import sys
import logging # Import logging module
from pwn import * # pip install pwntools
from hashpumpy import hashpump # pip install hashpumpy

# --- Configuración ---
HOST = "ctf.hackademics-forum.com"
PORT = 42836
# HOST = "localhost"
# PORT = 9999

# Set log level (DEBUG para ver hashes buscados y observados)
context.log_level = 'info' # Change to 'debug' for detailed logs

# --- Constantes ---
SECRET_LEN = 52
pad_secret = b'\x80\x00\x00\x00\xa0\x01\x00\x00\x00\x00\x00\x00'
obstacle_hex = pad_secret.hex()
PROMPT_DELIMITER = b'Avisa de un obst\xc3\xa1culo: '
FINAL_PROMPT_DELIMITER = b'Secreto: '

log.info(f"Usando obstáculo (padding MD5 para {SECRET_LEN} bytes): {obstacle_hex}")

# --- Función para encontrar un byte específico (CORREGIDA) ---
def find_specific_byte(k, known_prefix, observed_hashes, bus_id):
    """Intenta encontrar el byte en la posición k."""
    log.info(f"Buscando byte {k}...")

    for b in range(256):
        current_guess = known_prefix + bytes([b])
        # La longitud del sufijo que prueba este byte 'b' es k+1
        target_L_s = k + 1
        suffix_data = current_guess # current_guess tiene longitud k+1

        try:
            # Calcular el hash para la longitud completa del prefijo actual
            computed_hash, _ = hashpump(bus_id, b'A', suffix_data, SECRET_LEN)
            computed_hash_lower = computed_hash.lower()

            if context.log_level == logging.DEBUG:
                 log.debug(f"  k={k}, b={hex(b)}, target_L_s={target_L_s}: Calculado H={computed_hash_lower}")

            # Verificar si ESTE hash específico (para la longitud k+1) fue observado
            if computed_hash_lower in observed_hashes:
                log.success(f"Encontrado byte {k}: {hex(b)} (coincidencia para L_s={target_L_s})")
                return b # Encontramos el byte correcto, devolverlo inmediatamente

        except Exception as e:
            # Logueamos el error pero continuamos por si es transitorio o solo afecta a un 'b'
            log.error(f"Error en hashpump: k={k}, b={hex(b)}, L_s={target_L_s}: {e}")
            continue

    # Si después de probar los 256 bytes, no encontramos una coincidencia *para L_s=k+1*
    log.error(f"No se pudo encontrar el byte {k}. No hubo coincidencia para L_s={k+1}.")
    return -1 # Indicar fallo


# --- Main Script ---
try:
    conn = remote(HOST, PORT)
except PwnlibException as e:
    log.error(f"Error conectando a {HOST}:{PORT} - {e}")
    sys.exit(1)

try:
    # --- Extraer bus_id ---
    banner_data = conn.recvuntil(PROMPT_DELIMITER, timeout=10)
    if not banner_data: raise EOFError("No se recibió banner o prompt inicial.")
    print(banner_data.decode(errors='ignore'))
    bus_id = ""
    lines = banner_data.split(b'\n')
    for line in lines:
        parts = line.strip().split(b'|')
        if len(parts) >= 3 and len(parts[1]) == 32:
             potential_id = parts[1].decode('ascii', errors='ignore')
             if all(c in '0123456789abcdefABCDEF' for c in potential_id):
                 bus_id = potential_id.lower()
                 break
    if not bus_id: raise ValueError("No se pudo extraer bus_id del banner.")
    log.success(f"Extraído bus_id: {bus_id}")

    # --- Fase 1: Recolección de Hashes ---
    observed_hashes = set()
    log.info("Recolectando 1000 hashes...")
    # ProgressBar si quieres: p = log.progress('Recolectando')
    for i in range(1000):
        # p.status(f"{i+1}/1000, Únicos: {len(observed_hashes)}")
        try:
            conn.sendline(obstacle_hex.encode())
            response_line = conn.recvline(timeout=2)
            if not response_line:
                log.warning(f"No hubo respuesta en iteración {i}, continuando...")
                continue
            response = response_line.strip().decode()
            if len(response) == 32 and all(c in '0123456789abcdefABCDEF' for c in response):
                observed_hashes.add(response.lower())
            elif len(response) > 0:
                 if "Avisa" not in response and "Secreto" not in response and "Mike" not in response: # Evitar logs de ruido
                    log.warning(f"Respuesta inválida/inesperada en iteración {i}: '{response[:50]}...'")

            if i < 999:
                prompt = conn.recvuntil(PROMPT_DELIMITER, timeout=2)
                if not prompt.endswith(PROMPT_DELIMITER):
                     log.warning(f"Prompt inesperado o conexión cerrada después de iteración {i}.")
                     # print(f"Recibido en lugar de prompt: {prompt}")
                     break
            if context.log_level != logging.DEBUG and (i + 1) % 100 == 0 :
                 log.info(f"Recolectados {i+1}/1000 hashes. Únicos: {len(observed_hashes)}")
        except EOFError as e:
            log.error(f"Conexión cerrada durante recolección (iteración {i}): {e}")
            break
        except Exception as e:
            log.error(f"Error durante recolección (iteración {i}): {e}")
            break
    # p.success(f"Únicos: {len(observed_hashes)}")
    log.success(f"Recolección finalizada. Hashes únicos observados: {len(observed_hashes)}")
    if not observed_hashes: raise ValueError("No se recolectaron hashes válidos.")
    # Es bueno tener 53, pero el script ahora DEBE tener el hash para la longitud k+1 para encontrar el byte k
    if len(observed_hashes) < SECRET_LEN + 1 :
         log.warning(f"Se recolectaron solo {len(observed_hashes)} hashes únicos (<53). Podría fallar la recuperación.")

    # --- DEBUG: Imprimir hashes observados si el nivel de log es debug ---
    if context.log_level == logging.DEBUG:
        log.debug("Hashes observados:")
        sorted_hashes = sorted(list(observed_hashes))
        for h in sorted_hashes:
            log.debug(f"  {h}")
        log.debug(f"Total hashes únicos: {len(sorted_hashes)}")
    # --- FIN DEBUG ---

    # --- Fase 2: Recuperación Byte a Byte usando la función (CORREGIDA) ---
    known_prefix = b''
    log.info("Iniciando recuperación byte a byte...")
    for k in range(SECRET_LEN):
        byte_val = find_specific_byte(k, known_prefix, observed_hashes, bus_id)

        if byte_val == -1:
             # Si falla, imprimir hashes observados puede ayudar (especialmente si context != debug)
             if context.log_level != logging.DEBUG:
                 log.error("Hashes observados (puede ayudar a depurar):")
                 sorted_hashes = sorted(list(observed_hashes))
                 for h_idx, h in enumerate(sorted_hashes):
                     log.error(f"  {h_idx}: {h}")
             raise ValueError(f"No se pudo recuperar el byte {k}.")
        else:
            known_prefix += bytes([byte_val])
            log.info(f"Prefijo actual ({k+1}/{SECRET_LEN}): {known_prefix.hex()}")


    # --- Fase 3: Enviar Secreto y Obtener Flag ---
    log.success("¡Secreto recuperado completamente!")
    log.info(f"Secreto (hex): {known_prefix.hex()}")
    try: log.info(f"Secreto (ascii?): {known_prefix.decode('ascii', errors='replace')}")
    except Exception: pass

    conn.recv(timeout=0.1) # Limpiar buffer
    final_prompt = conn.recvuntil(FINAL_PROMPT_DELIMITER, timeout=5)
    if not final_prompt.endswith(FINAL_PROMPT_DELIMITER):
         log.warning("No se recibió el prompt final 'Secreto: '. Intentando enviar de todas formas.")
         # print(f"Recibido en lugar de prompt final: {final_prompt}")
    log.info("Enviando secreto recuperado...")
    conn.sendline(known_prefix.hex().encode())
    log.info("Esperando respuesta final...")
    result = conn.recvall(timeout=10).decode(errors='ignore')
    log.success("Respuesta recibida:")
    print("-" * 20)
    print(result.strip())
    print("-" * 20)

except (ValueError, EOFError, PwnlibException) as e:
     log.error(f"Error en script: {e}")
except Exception as e:
    log.critical(f"Error inesperado: {e}")
    import traceback
    traceback.print_exc()
finally:
    if 'conn' in locals() and conn and conn.connected:
        conn.close()
        log.info("Conexión cerrada.")
