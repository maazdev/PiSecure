import os
import json
import base64
from Crypto.Random import get_random_bytes

def rs(username):
  path = f"{os.getcwd()}/Images/"
  if not os.path.exists(path):
    os.mkdir(path)
  if os.path.exists(f"{path}{username}"):
    return -1, path
  elif not os.path.exists(f"{path}{username}"):
    os.mkdir(f"{path}{username}")
    filename = f"{path}{username}/{username}.json"
    # Create new salt json with username
    salt = get_random_bytes(16)
    # Dumping salt into json
    salto = base64.b64encode(salt).decode("utf-8")
    result = json.dumps({'salt': salto})
    with open(filename, 'w') as  f:
      json.dump(result, f)
    return salt, path