#!/usr/bin/env python3
from pwn import *
import ctypes
import sys

# --- Remote Target ---
HOST = "ctf.hackademics-forum.com"
PORT = 53921
# --- End Remote Target ---

# --- Configuration ---
USERNAME_LENGTH = 1      # Seed for srand
USERNAME = "A" * USERNAME_LENGTH
# --- End Configuration ---

# 1. Wordlist (La que proporcionaste, con "flag" en índice 95)
#    Index 0 -> "mezquita", Index 95 -> "flag", Index 99 -> "torrox"
wordlist = [
    "mezquita", "califato", "medina", "alcazar", "patios", "flamenco", "guitarra", "feria", "romeria", "cruces",        # 0-9
    "juderia", "mayo", "puente_romano", "guadalquivir", "calahorra", "molinos", "calleja", "caballo", "flores", "gitana", # 10-19
    "montilla", "moriles", "vino", "aceite", "olivo", "sierra", "subbetica", "hornazo", "salmorejo", "flamenquin",      # 20-29
    "rabo", "naranjos", "alminar", "ermita", "sierra", "UCO", "fuensanta", "cordobes", "cordobesa", "torero",            # 30-39
    "museo", "medina_azahara", "sombra", "azulejos", "calesa", "cogolludo", "arruzafa", "albolafia", "sotos", "san_basilio", # 40-49
    "catedral", "cristianos", "musulmanes", "mudejar", "barroco", "renacimiento", "cofradia", "semana_santa", "paso", "costalero",# 50-59
    "saeta", "campanas", "caballerizas", "capilla", "naibu3", "fernandinas", "rejas", "gruta", "baños_arabes", "pozoblanco", # 60-69
    "priego", "lucena", "montoro", "cabra", "zuheros", "baena", "villafranca", "pedroches", "encina", "parque_natural", # 70-79
    "califa", "abderraman", "alhakem", "omeya", "azahara", "carmona", "picon", "acebuchal", "madinat", "arruzafilla",    # 80-89
    "portichuelo", "triana", "fuensantilla", "alcolea", "almodovar", "flag", "Hackademics", "guadalbarbo", "Aula_Ciberseguridad_y_Redes", "torrox" # 90-99
]

# Verificar que tenemos 100 palabras
if len(wordlist) != 100:
    log.error(f"La lista de palabras tiene {len(wordlist)} elementos, se esperaban 100.")
    sys.exit(1)
log.info("Lista de 100 palabras cargada.")

# 2. Generar la secuencia usando LOCAL libc (ASUME remote usa compatible libc/rand)
try:
    # Intenta cargar la libc estándar del sistema
    libc = ctypes.CDLL(None)
    libc.srand.argtypes = [ctypes.c_uint]
    libc.srand.restype = None
    libc.rand.argtypes = []
    libc.rand.restype = ctypes.c_int
except Exception as e:
    log.error(f"Error al cargar libc local o sus funciones (srand/rand): {e}")
    log.error("No se puede predecir la secuencia sin libc.")
    sys.exit(1)

seed = USERNAME_LENGTH
libc.srand(seed)
log.info(f"Generando secuencia de palabras para seed = {seed} (usando libc local)...")

sequence = []
indices_generated = [] # Para debug si falla
for i in range(100):
    # rand() % 100
    index = libc.rand() % 100
    indices_generated.append(index)
    if index < 0 or index >= len(wordlist):
         log.error(f"Índice local generado inválido: {index} en la ronda {i+1}")
         sys.exit(1)
    # Comprobación extra (paranoia)
    if wordlist[index] is None:
         log.error(f"La palabra en el índice {index} es None. Revisa la lista.")
         sys.exit(1)

    sequence.append(wordlist[index])


log.success("Secuencia de 100 palabras generada.")
# Descomenta para ver los índices que se usarán:
# log.info(f"Indices a usar: {indices_generated}")
# log.info(f"Secuencia a enviar: {sequence}")


# 3. Interactuar con el servicio REMOTO
log.info(f"Conectando a {HOST}:{PORT}...")
try:
    # Cambiamos process por remote
    p = remote(HOST, PORT, timeout=5) # Timeout general de conexión
except Exception as e:
    log.error(f"Fallo al conectar a {HOST}:{PORT}: {e}")
    sys.exit(1)

# Enviar nombre de usuario
p.recvuntil(b"Introduce un nombre de usuario: ")
log.info(f"Enviando username: '{USERNAME}' (longitud {USERNAME_LENGTH})")
p.sendline(USERNAME.encode())

# Recibir debug y prompt inicial
# Intentar recibir la línea de debug, pero no fallar si no está (importante para remoto)
try:
    debug_line = f"[DEBUG] Numero de caracteres: {USERNAME_LENGTH}\n".encode()
    p.recvuntil(debug_line, timeout=2) # Timeout corto por si no existe
    log.info("Debug de longitud de caracteres recibido.")
except EOFError:
    log.warning("El servidor cerró la conexión inesperadamente después de enviar el nombre.")
    p.close()
    sys.exit(1)
except Exception as e:
    log.warning(f"No se recibió la línea de debug (o hubo timeout): {e}. Continuando...")

# Esperar el siguiente prompt conocido
p.recvuntil(b'Adivina las 100 palabras secretas.\n')
log.info("Comenzando a adivinar...")

# Enviar la secuencia de palabras
for i, word in enumerate(sequence):
    round_num = i + 1
    prompt = f"Palabra {round_num}: ".encode()
    try:
        p.recvuntil(prompt, timeout=3) # Timeout para esperar el prompt
        log.info(f"Enviando palabra {round_num}/{len(sequence)}: {word}")
        p.sendline(word.encode())

        # Esperar confirmación "Correcto!" (ignorar líneas vacías)
        # Leeremos línea a línea hasta encontrar "Correcto!" o error/EOF
        resp = b""
        while b"Correcto!" not in resp:
             line = p.recvline(timeout=2).strip() # Timeout para la respuesta
             if not line: # Puede que envíe línea vacía antes de "Correcto!"
                 continue
             resp = line
             # Si la respuesta no es "Correcto!" y no está vacía, algo va mal
             if b"Correcto!" not in resp:
                 log.error(f"Respuesta inesperada en ronda {round_num} después de enviar '{word}': {resp.decode()}")
                 log.info("¿Quizás la predicción de libc fue incorrecta o la palabra 96 ('flag') fue errónea?")
                 log.info(f"Índice para esta ronda: {indices_generated[i]}")
                 p.interactive()
                 sys.exit(1)
        # log.success(f"Ronda {round_num} correcta.") # Descomentar para más verbosidad


    except EOFError:
        log.error(f"El proceso remoto terminó inesperadamente en la ronda {round_num}.")
        log.error("Posibles causas: Predicción de libc incorrecta, palabra inválida (ej: índice 95?), crash del servidor.")
        log.info(f"Índice que se intentaba usar: {indices_generated[i]}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Error durante la interacción en ronda {round_num}: {e}")
        p.interactive()
        sys.exit(1)

# 4. Recibir la flag
log.success("¡Las 100 palabras fueron aceptadas!")
log.info("Esperando la flag...")
try:
    # Leer el mensaje final antes de la flag
    p.recvuntil(b"Imposible que hayas ganado, seguro que hiciste trampas! Xb\n", timeout=3)
    # Leer la flag (puede tener varias líneas o estar justo después)
    flag = p.recvall(timeout=3).decode().strip() # Lee todo lo restante con timeout
    log.success("Respuesta recibida después del mensaje de éxito:")
    # Imprimir tal cual, ya que la flag podría no tener el formato esperado
    print("--- INICIO FLAG ---")
    print(flag)
    print("--- FIN FLAG ---")

except Exception as e:
    log.error(f"Error recibiendo la flag o el proceso terminó antes de tiempo: {e}")
    log.info("Asegúrate de que el mensaje 'Imposible que hayas ganado...' es correcto.")
    p.interactive() # Intentar ver qué quedó en el buffer

p.close()
log.info("Conexión cerrada.")
