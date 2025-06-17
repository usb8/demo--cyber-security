from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
KEY = os.urandom(16)
IV = os.urandom(16)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    ciphertext = bytes.fromhex(request.json["data"])
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        plaintext = unpad(cipher.decrypt(ciphertext), 16)
        return {"status": "OK"}
    except ValueError:
        return {"status": "PaddingError"}, 403

app.run(port=5000)
