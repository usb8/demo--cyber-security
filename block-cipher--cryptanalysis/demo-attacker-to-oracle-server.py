import requests
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BLOCK_SIZE = 16
URL = "http://localhost:5000/decrypt"

# Example of plaintext
plaintext = b"Secret message here!"
KEY = os.urandom(BLOCK_SIZE)
IV = os.urandom(BLOCK_SIZE)

# Encrypt plaintext as server does
cipher = AES.new(KEY, AES.MODE_CBC, IV)
ciphertext = IV + cipher.encrypt(pad(plaintext, BLOCK_SIZE))

# Split block
blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

def padding_oracle(modified_ciphertext):
    data = modified_ciphertext.hex()
    response = requests.post(URL, json={"data": data})
    return response.status_code != 403  # True if padding is valid

# Attack the last block
def attack_block(prev_block, target_block):
    recovered = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)

    for i in reversed(range(BLOCK_SIZE)):
        pad_byte = BLOCK_SIZE - i
        prefix = bytearray(os.urandom(i))

        # Prepare fake block
        for guess in range(256):
            test_block = bytearray(prefix)
            test_block.append(guess)

            for j in range(BLOCK_SIZE - i - 1):
                # Use the intermediate value found
                test_block.append(intermediate[i + 1 + j] ^ pad_byte)

            fake = bytes(test_block) + target_block
            fake_prev = test_block + target_block
            fake_full = bytes(test_block) + target_block

            full_cipher = b''.join(blocks[:-2]) + bytes(test_block) + target_block

            if padding_oracle(full_cipher):
                intermediate[i] = guess ^ pad_byte
                recovered[i] = intermediate[i] ^ prev_block[i]
                break

    return recovered

recovered_plain = attack_block(blocks[-2], blocks[-1])
print("Recovered plaintext:", recovered_plain.decode())

"""
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
