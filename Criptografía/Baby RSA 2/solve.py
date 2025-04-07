import math # Importar math
from Crypto.Util.number import long_to_bytes, inverse

# --- Leer valores del archivo ---
vals = {}
try:
    with open("output.txt", "r") as f:
        for line in f:
            try:
                key, value = line.strip().split(" = ", 1)
                vals[key.strip()] = int(value.strip())
            except ValueError:
                print(f"Advertencia: No se pudo parsear la línea: {line.strip()}")
                continue # Saltar líneas mal formadas
except FileNotFoundError:
    print("Error: output.txt no encontrado.")
    exit(1)
except Exception as e:
    print(f"Error leyendo output.txt: {e}")
    exit(1)

# --- Asignar valores ---
required_keys = ['e', 'n', 'phi_enc', 'pplusq_enc', 'ct']
if not all(key in vals for key in required_keys):
    print("Error: Faltan valores requeridos en output.txt.")
    print(f"Requeridos: {required_keys}")
    print(f"Encontrados: {list(vals.keys())}")
    exit(1)

e = vals['e']
n = vals['n']
phi_enc = vals['phi_enc']
pplusq_enc = vals['pplusq_enc']
ct = vals['ct']

print("--- Valores leídos ---")
print(f"e = {e}")
print(f"n = {n}")
print(f"phi_enc = {phi_enc}")
print(f"pplusq_enc = {pplusq_enc}")
print(f"ct = {ct}")
print("-" * 30)

# --- Ataque Franklin-Reiter (fórmula e=3) ---
print("\nIniciando Ataque Franklin-Reiter (sin Sage)...")

# S = (1 + 2*pplusq_enc - phi_enc) * pow(pplusq_enc + phi_enc + 2, -1, n) mod n
num = (1 + 2 * pplusq_enc - phi_enc) % n
den = (pplusq_enc + phi_enc + 2) % n

print(f"Numerador (1 + 2*c1 - c2) mod n = {num}")
print(f"Denominador (c1 + c2 + 2) mod n = {den}")

# Calcular inverso modular del denominador
common_divisor = math.gcd(den, n)

if common_divisor > 1 and common_divisor != n: # Asegurar que el divisor es útil
    print(f"\n¡Éxito! El denominador comparte un factor con n.")
    p = common_divisor
    q = n // p
    if p * q == n:
        print(f"Factores encontrados directamente por GCD:")
        print(f"p = {p}")
        print(f"q = {q}")
        # Saltar al cálculo de 'd' y descifrado
    else:
        print("Error: El GCD no dio un factor útil de n.")
        exit(1)
elif common_divisor == n:
     print("Error: El denominador es múltiplo de n, no se puede calcular el inverso.")
     exit(1)
else:
    # El inverso existe, calcular S
    print("\nCalculando inverso modular del denominador...")
    try:
        den_inv = inverse(den, n)
        print("Inverso modular calculado.")
    except ValueError:
        print(f"Error: No se pudo calcular el inverso modular del denominador ({den}), aunque GCD era 1?")
        print(f"GCD({den}, {n}) = {math.gcd(den, n)}")
        exit(1)

    S = (num * den_inv) % n
    print(f"\nS (p+q) recuperado = {S}")

    # --- Verificar S ---
    print("Verificando S...")
    s_check = pow(S, e, n)
    phi_val_check = (n - S + 1) % n
    phi_enc_check = pow(phi_val_check, e, n)

    if s_check == pplusq_enc and phi_enc_check == phi_enc:
        print("Verificación de S exitosa.")

        # --- Factorizar n usando S = p+q ---
        print("\nFactorizando n usando S = p+q...")
        # Resolver x^2 - S*x + n = 0
        # Las raíces son (S +/- sqrt(S^2 - 4n)) / 2
        delta_sq = (S*S - 4*n)
        
        # Asegurarse que el discriminante no es negativo (no debería serlo si S es correcto)
        if delta_sq < 0:
             print(f"Error: Discriminante (S^2 - 4n) es negativo: {delta_sq}")
             exit(1)

        # Calcular raíz cuadrada entera usando math.isqrt (Python 3.8+)
        try:
             print(f"Calculando isqrt({delta_sq})...")
             delta = math.isqrt(delta_sq) # <--- CAMBIO CLAVE
             print(f"isqrt = {delta}")
        except ValueError:
             print(f"Error: No se pudo calcular la raíz cuadrada entera de {delta_sq} (¿negativo?)")
             exit(1)
        except AttributeError:
             print("Error: math.isqrt no disponible. ¿Estás usando Python < 3.8?")
             print("Considera actualizar Python o usar la función i_sqrt modificada (Opción 2).")
             exit(1)

        # Verificar si delta_sq era un cuadrado perfecto
        if delta * delta != delta_sq:
             print(f"Error: S^2 - 4n ({delta_sq}) no es un cuadrado perfecto. No se pueden encontrar p, q enteros.")
             print(f"Raíz calculada: {delta}")
             print(f"Raíz al cuadrado: {delta*delta}")
             exit(1)

        p = (S + delta) // 2
        q = (S - delta) // 2

        # Verificar factores
        if p * q == n:
            print("Factorización exitosa:")
            print(f"p = {p}")
            print(f"q = {q}")
        else:
            print("Error: La factorización falló (p*q != n).")
            print(f"p calculado = {p}")
            print(f"q calculado = {q}")
            print(f"p * q = {p * q}")
            exit(1)
    else:
        print("Error: La verificación de S falló.")
        print(f"pow(S, e, n) = {s_check} (esperado {pplusq_enc})")
        print(f"pow(n-S+1, e, n) = {phi_enc_check} (esperado {phi_enc})")
        exit(1)

# --- Calcular d y Descifrar ---
# (Este bloque se ejecuta si se factorizó n, ya sea por GCD o por S)
print("\nCalculando clave privada y descifrando...")
phi = (p - 1) * (q - 1)
print(f"Phi calculado = {phi}")

try:
    d = inverse(e, phi)
    print(f"Clave privada d calculada = {d}")
except ValueError:
    print(f"Error: e={e} no es invertible módulo phi={phi}. GCD={math.gcd(e, phi)}")
    exit(1)

# Descifrar
m_int = pow(ct, d, n)
print(f"\nMensaje descifrado (entero): {m_int}")

# Convertir a bytes
try:
    flag_bytes = long_to_bytes(m_int)
    print(f"Mensaje descifrado (bytes): {flag_bytes}")
    # Intentar decodificar como UTF-8
    try:
        flag_str = flag_bytes.decode('utf-8')
        print(f"\nFLAG: {flag_str}")
    except UnicodeDecodeError:
        print("\nNo se pudo decodificar como UTF-8, mostrando bytes crudos.")

except OverflowError:
     print("Error: El entero descifrado es demasiado grande para convertir a bytes.")
except Exception as ex:
     print(f"Error al convertir a bytes: {ex}")
