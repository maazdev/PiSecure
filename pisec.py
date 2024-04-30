import os
import json
import base64
import matplotlib.image as img
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def encrypt(ukey, path, ctr, username):
    # Pointing to image
    imgpath = f"{path}{username}/image{ctr}.jpg"
    #Reading image
    n = img.imread(imgpath)
    # Encrypting image
    cipher = ChaCha20.new(key = ukey, nonce = get_random_bytes(24))
    ciphertext = cipher.encrypt(n.tobytes())
    nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    ct = base64.b64encode(ciphertext).decode('utf-8')
    # Dumping encrypted image into json
    result = json.dumps({'nonce': nonce, 'ciphertext': ct, 'shape': n.shape})
    with open(f"{path}{username}/encryptedimage{ctr}.json", 'w') as  f:
        json.dump(result, f)
    os.remove(imgpath)
    return 1