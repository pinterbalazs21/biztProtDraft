from Crypto.Hash import SHA256

import os

def getHash(payload):
    h = SHA256.new()
    h.update(payload)
    return h.hexdigest()

def getFileInfo(path):
    size = os.path.getsize(path)
    file = open(path, "r")
    fileHash = getHash(file.read().encode("utf-8"))
    return fileHash, size