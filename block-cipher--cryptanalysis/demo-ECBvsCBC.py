from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

BLOCK_SIZE = 16
KEY = os.urandom(BLOCK_SIZE)

def encrypt_image(image_path, mode="ECB"):
    img = Image.open(image_path).convert("RGB")
    data = bytes(img.tobytes())
    padded = pad(data, BLOCK_SIZE)

    if mode == "ECB":
        cipher = AES.new(KEY, AES.MODE_ECB)
    elif mode == "CBC":
        iv = os.urandom(BLOCK_SIZE)
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
    else:
        raise ValueError("Mode not supported")

    encrypted = cipher.encrypt(padded)
    encrypted_img = Image.frombytes("RGB", img.size, encrypted[:img.width * img.height * 3])
    encrypted_img.save(f"./source/output/penguin_{mode}.bmp")

encrypt_image("./source/input/pg.bmp", "ECB")
encrypt_image("./source/input/pg.bmp", "CBC")
