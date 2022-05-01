from Crypto.Hash import SHA256

def getHash(payload):
    h = SHA256.new()
    h.update(payload)
    return h.hexdigest()
