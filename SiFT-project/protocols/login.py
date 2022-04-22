import sys
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import HKDF

class LoginProtocol:
    def __init__(self, MTP):
        self.loginHash = ''
        self.MTP = MTP

    def load_publickey(self, pubkeyfile):
        with open(pubkeyfile, 'rb') as f:
            pubkeystr = f.read()
        try:
            return RSA.import_key(pubkeystr)
        except ValueError:
            print('Error: Cannot import public key from file ' + pubkeyfile)
            sys.exit(1)

    def encryptLoginReq(self, loginReq):  # loginReq == payload
        print("Encrypting login req")
        tk = Random.get_random_bytes(32)
        msgLen = 16 + len(loginReq) + 12 + 256  # length of header, (encripted) payload, auth mac + ETK
        msg = self.MTP.encryptAndAuth(b'\x00\x00', loginReq, msgLen, tk)
        pubkey = self.load_publickey("public.key")
        RSAcipher = PKCS1_OAEP.new(pubkey)
        etk = RSAcipher.encrypt(tk)
        return msg + etk, tk

    def encryptLoginResp(self, payload, tk):
        print("Encrypting login response")
        loginRes = self.createLoginRes(payload)
        hash = loginRes[0:64]
        rand = loginRes[65:]
        msgLen = 12 + len(loginRes) + 16
        response = self.MTP.encryptAndAuth(b'\x00\x10', loginRes, msgLen, tk)
        return response, hash, rand

    def createLoginReq(self, username, password):
        rand = Random.get_random_bytes(16).hex()
        loginReq = str(time.time_ns()) + '\n' + username + '\n' + password + '\n' + rand
        self.loginHash = self.getHash(loginReq.encode("utf-8"))
        return loginReq, rand  # type: str

    def createLoginRes(self, recievedPayloadStr):
        rand = Random.get_random_bytes(16).hex()
        strResponse = self.getHash(recievedPayloadStr) + '\n' + rand  # type: str
        return strResponse.encode("utf-8")  # request hash + random bytes,

    def decryptLoginReqest(self, rawMSG, keypair):
        #accepts and verifies loginRequests
        # decripting encrypted temporary key
        etk = rawMSG[-256:]
        RSAcipher = PKCS1_OAEP.new(keypair)
        tk = RSAcipher.decrypt(etk)
        # decripting msg using the tk
        msg = rawMSG[:-256]
        loginReq = self.MTP.decryptAndVerify(msg, tk)
        return loginReq, tk

    def decryptLoginRes(self, tk, msg):
        payload = self.MTP.decryptAndVerify(msg, tk)
        # üzenetben stringként 1 byte == 2 hexa szám-->64 hosszú str
        if self.loginHash != payload[0:64].decode('utf-8'):
            print("Wrong Hash Value")
        return payload

    def getHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        return h.hexdigest()

    def createFinalKey(self, ikey, salt):
        self.MTP.finalKey = HKDF(ikey, 32, salt, SHA256)
        print("Final key constructed:")
        print(self.MTP.finalKey)
