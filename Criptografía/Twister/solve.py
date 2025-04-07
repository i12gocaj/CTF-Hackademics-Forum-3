#!/usr/bin/env python3

from pwn import *
from randcrack import RandCrack
import re

# Helper function identical to the server's one
def rebase(n):
    if n < 64:
        return [n]
    else:
        # Correctly handle the recursive base conversion (LSD first)
        # The original implementation is correct for its purpose (LSD first list)
        res = []
        if n == 0: return [0] # Handle base case n=0 if needed, though getrandbits(32) > 0 mostly
        while n > 0:
             res.append(n % 64)
             n //= 64
        return res # Returns [lsd, ..., msd] - wait, let's stick to server's impl exactly
        # Server impl: return [n % 64] + rebase(n//64) --> returns [lsd, ..., msd]
        # Okay, server's rebase IS LSD first.

# Server rebase implementation (verified)
def server_rebase(n):
    if n < 64:
        return [n]
    # Handle n=0 case explicitly
    if n == 0:
        return [0]
    # Use iterative approach to avoid potential recursion depth issues for large n (though unlikely here)
    l = []
    temp_n = n
    while temp_n > 0:
        l.append(temp_n % 64)
        temp_n //= 64
    # Server's recursive approach actually produces [lsd, ..., msd] list
    # Example: server_rebase(100) -> [36, 1] because 100 = 36*64^0 + 1*64^1
    # The iterative version produces the same [lsd, ..., msd] order.
    return l


# --- Configuration ---
HOST = "ctf.hackademics-forum.com"
PORT = 15364
NUM_OUTPUTS_NEEDED = 624 # For MT19937 (32-bit)
ROUNDS_TO_COLLECT = 4500 # Collect slightly more than needed just in case
prompt_bytes = b"\xc2\xbfQu\xc3\xa9 color va a salir? Formato: x,y. "

# --- Connect ---
conn = remote(HOST, PORT)

# --- Skip Banner ---
# Wait for the first actual question prompt after the banner/board
log.info("Waiting for the first prompt...")
conn.recvuntil(prompt_bytes)
log.info("First prompt received.")

# --- Data Collection Phase ---
log.info("Starting data collection phase...")
history = []
current_sequence = []
reconstructed_n_values = []
cracker = RandCrack()

for i in range(ROUNDS_TO_COLLECT):
    if len(reconstructed_n_values) >= NUM_OUTPUTS_NEEDED:
        log.success(f"Collected {len(reconstructed_n_values)} numbers, enough to crack.")
        break

    # Send dummy guess - use sendlineafter with the prompt bytes
    conn.sendline(b"0,0") # Send the guess first now

    # Receive response and extract actual result
    try:
        # Read until the result line starts
        conn.recvuntil(b"Resultado: [")
        result_line = conn.recvline().decode().strip() # e.g., "4, 4]" or similar
        match = re.match(r"(\d+),\s*(\d+)", result_line)
        if match:
            rx, ry = int(match.group(1)), int(match.group(2))
            popped = rx * 8 + ry
            log.debug(f"Round {i}: Server output [{rx}, {ry}], popped = {popped}")
            history.append(popped)
            current_sequence.append(popped)

            # --- Try to validate current_sequence ---
            if len(current_sequence) > 1:
                p_bitlen = current_sequence[0]
                digits = current_sequence[1:] # These were popped MSD first
                k = len(digits)

                # Reconstruct n
                n_candidate = 0
                try:
                    # The digits sequence is popped MSD first relative to the rebase list
                    # So digits[0] is MSD, digits[k-1] is LSD
                    for j in range(k):
                         n_candidate += digits[j] * (64**(k - 1 - j))
                except OverflowError:
                    # Skip if calculation overflows (unlikely with 32-bit n)
                    continue

                # --- Validation Checks ---
                valid = False
                if n_candidate >= 0: # Basic sanity check
                    # Check 1: Bit length
                    if n_candidate == 0 and p_bitlen == 0: # Special case for n=0
                         candidate_bit_length = 0
                    elif n_candidate > 0:
                         candidate_bit_length = n_candidate.bit_length()
                    else: # Should not happen for getrandbits
                         candidate_bit_length = -1

                    if candidate_bit_length == p_bitlen:
                        # Check 2 & 3: Rebase consistency
                        # server_rebase produces [lsd, ..., msd]
                        # The list `l` was rebase(n) + [bit_length] = [lsd,...,msd, bit_length]
                        # Popping order was: bit_length, msd, ..., lsd
                        # So `digits` should be equal to `reversed(rebase(n))`
                        try:
                            rb = server_rebase(n_candidate) # Uses server's logic [lsd, ..., msd]
                            # Compare reversed rebase list with the collected digits
                            if len(rb) == k and list(reversed(rb)) == digits:
                                valid = True
                        except RecursionError:
                             log.warning(f"Recursion error during rebase validation for n={n_candidate}")
                        except Exception as e:
                             log.warning(f"Other error during rebase validation: {e}")


                if valid:
                    log.info(f"Successfully reconstructed n = {n_candidate} (bitlen {p_bitlen}) from sequence {current_sequence}")
                    reconstructed_n_values.append(n_candidate)
                    try:
                        # randcrack expects 32 bits at a time
                        cracker.submit(n_candidate & 0xFFFFFFFF) # Ensure it's 32 bits
                    except ValueError as e:
                        log.error(f"RandCrack submission error for {n_candidate}: {e}")
                    # Start a new sequence
                    current_sequence = []

        else:
            log.error(f"Could not parse result line: {result_line}")
            conn.close()
            exit(1)

        # Need to wait for the *next* prompt before looping
        if len(reconstructed_n_values) < NUM_OUTPUTS_NEEDED and i < ROUNDS_TO_COLLECT -1 :
             conn.recvuntil(prompt_bytes)

    except EOFError:
        log.error("Connection closed unexpectedly during data collection.")
        exit(1)
    except Exception as e:
        log.error(f"An error occurred during collection: {e}")
        import traceback
        traceback.print_exc()
        conn.close()
        exit(1)

# Check if enough numbers were collected AFTER the loop
if len(reconstructed_n_values) < NUM_OUTPUTS_NEEDED:
    log.error(f"Failed to collect enough numbers ({len(reconstructed_n_values)}/{NUM_OUTPUTS_NEEDED}). Exiting.")
    conn.close()
    exit(1)

log.success("Data collection finished. State reconstruction successful.")

# --- Prediction Phase ---
log.info("Starting prediction phase...")
streak = 0
current_l = []

# Ensure we are at a prompt before starting prediction
conn.recvuntil(prompt_bytes)

while streak < 100:
    log.info(f"Current Streak: {streak}")
    if not current_l:
        try:
            # Predict the next 32-bit output
            predicted_n = cracker.predict_getrandbits(32)
            log.info(f"Predicted next n = {predicted_n}")
        except ValueError as e: # Might happen if cracker doesn't have enough data despite checks
            log.error(f"RandCrack prediction error: {e}. Trying to collect more data might be needed.")
            conn.close()
            exit(1)
        except IndexError as e: # Can happen if internal state is somehow corrupted
            log.error(f"RandCrack prediction IndexError: {e}. PRNG state might be wrong.")
            conn.close()
            exit(1)

        # Calculate the 'l' list based on the predicted n
        try:
             n_bit_length = predicted_n.bit_length() if predicted_n > 0 else 0
             # Remember: l = rebase(n) + [n.bit_length()]
             # And pop() takes from the end.
             # server_rebase returns [lsd, ..., msd]
             current_l = server_rebase(predicted_n) + [n_bit_length]
             log.debug(f"Calculated next l: {current_l}")
        except RecursionError:
             log.error(f"Recursion error generating l for predicted n={predicted_n}")
             conn.close()
             exit(1)
        except Exception as e:
             log.error(f"Error generating l: {e}")
             conn.close()
             exit(1)


    if not current_l:
        log.error("Calculated 'l' is empty, cannot proceed.")
        conn.close()
        exit(1)

    # Get the next value to be popped (last element)
    next_pop = current_l.pop()
    log.debug(f"Next popped value: {next_pop}, remaining l: {current_l}")

    # Calculate predicted coordinates
    predict_x = next_pop // 8
    predict_y = next_pop % 8

    # Send prediction
    prediction_str = f"{predict_x},{predict_y}".encode()
    log.info(f"Sending prediction: {prediction_str.decode()}")
    # Use sendline directly, as we already consumed the prompt
    conn.sendline(prediction_str)

    # Check result
    response_line1 = conn.recvline()
    if b"Correcto!" in response_line1:
        streak += 1
        log.success(f"Correct! Streak: {streak}")
        # Consume the "Resultado: [...]" line
        conn.recvuntil(b"Resultado: [")
        conn.recvline()
    elif b"Sigue intent" in response_line1: # Match "Sigue intentándolo!"
        log.warning("Incorrect prediction. Resetting streak.")
        streak = 0
        # Consume the "Resultado: [...]" line
        conn.recvuntil(b"Resultado: [")
        result_line = conn.recvline().decode().strip()
        log.info(f"Server actual result was: {result_line[:-1]}") # Show what it actually was
    else:
        log.error(f"Unexpected response: {response_line1.decode()}")
        conn.close()
        exit(1)

    # If streak < 100, wait for the next prompt
    if streak < 100:
        try:
            conn.recvuntil(prompt_bytes)
        except EOFError:
            log.error("Connection closed while waiting for next prompt in prediction phase.")
            if streak == 100: # Maybe we got the flag just before closing? Unlikely.
                 log.info("Checking if flag was received just before close...")
                 # Try reading remaining buffer - might be fragile
                 print(conn.recvall(timeout=1).decode())
            exit(1)


# --- Get Flag ---
if streak == 100:
    log.success("Streak of 100 achieved!")
    # The server prints two lines before the flag after the last "Correcto!" and "Resultado: [...]"
    # We should have already consumed those. The next lines should be the win message and flag.
    try:
        print(conn.recvline().decode().strip()) # ¿Cuál es el siguiente número...?
        print(conn.recvline().decode().strip()) # The flag line
    except EOFError:
        log.error("Connection closed before flag could be read.")
else:
    log.error("Failed to reach streak of 100.")

conn.close()
