from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
KEY = b'This is a key123'     # Fixed 16 bytes key for attacker to use
IV = b'This is an IV456'      # Fixed IV 16 bytes

@app.route("/decrypt", methods=["POST"])
def decrypt():
    ciphertext = bytes.fromhex(request.json["data"])
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        plaintext = unpad(cipher.decrypt(ciphertext), 16)
        return {"status": "OK"}
    except ValueError:
        return {"status": "PaddingError"}, 403

@app.route("/ciphertext", methods=["GET"])
def get_ciphertext():
    plaintext = b"Attack at dawn!!"  # exactly 16 bytes for easy handling
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = IV + cipher.encrypt(pad(plaintext, 16))
    return {"ciphertext": ct.hex()}

app.run(port=5000)
