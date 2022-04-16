import sys
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random

#key = b'0123456789abcdef0123456789abcdef'


class MTP:
    def __init__(self):
        self.loginHash = ''
        self.sqn = 1
        self.rcvsqn = 0
        print('MTP_INIT')

    def createHeader(self, typ, msg_length):
        # create header
        header_version = b'\x01\x00' #v1.0
        header_type = typ #2B, 10 possible value. 1st byte: interaction , 2nd byte: 1st nibble: request or response 2nd nibble: sub-types
        header_length = msg_length.to_bytes(2, byteorder='big') #2B, message length in bytes, including header
        header_sqn = (self.sqn + 1).to_bytes(2, byteorder='big')  #2B next message sequence number (encoded on 4 bytes)
        header_rnd = Random.get_random_bytes(6) #6B, random bytes
        header_rsv = b'\x00\x00'
        return header_version + header_type + header_length + header_sqn + header_rnd + header_rsv

    def decryptAndVerify(self,key ,msg):#nonce: sqn + rnd
        header = msg[0:16]
        encrypted_payload = msg[16:-12]
        nonce = header[6:14] #sqn:header[6:8], rnd = header[8:14]
        authtag = msg[-12:]
        msg_length = header[4:6]
        header_sqn = header[6:8]
        if len(msg) != int.from_bytes(msg_length, byteorder='big'):
            print("Warning: Message length value in header is wrong!")
            print("Processing is continued nevertheless...")

        #rcvsqn = 0 # todo store and update recent sqn
        print("Expecting sequence number " + str(self.rcvsqn + 1) + " or larger...")
        sndsqn = int.from_bytes(header_sqn, byteorder='big')
        if (sndsqn <= self.rcvsqn):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            sys.exit(1)
        self.rcvsqn += 1
        print("Sequence number verification is successful.")
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header)
        try:
            payload = AE.decrypt_and_verify(encrypted_payload, authtag)
        except Exception as e:
            print("Error: Operation failed!")
            print("Processing completed.")
            sys.exit(1)
        print("Operation was successful: message is intact, content is decrypted.")
        return payload

    def encriptAndAuth(self,key ,typ, payload, msg_length):
        header = self.createHeader(typ, msg_length)#todo sqn MTPselfben tárolni vagy máshol?
        nonce = header[6:14] #sqn:[6:8], rnd = [8:14]
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header)
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)
        self.sqn += 1
        return header + encrypted_payload + authtag#msg

    def load_publickey(self, pubkeyfile):
        with open(pubkeyfile, 'rb') as f:
            pubkeystr = f.read()
        try:
            return RSA.import_key(pubkeystr)
        except ValueError:
            print('Error: Cannot import public key from file ' + pubkeyfile)
            sys.exit(1)

    def encryptLoginReq(self, loginReq): # loginReq == payload
        print("Encrypting login req")
        tk = Random.get_random_bytes(32)
        msgLen = 16 + len(loginReq) + 12 + 256 #length of header, (encripted) payload, auth mac + ETK
        msg = self.encriptAndAuth(tk, b'\x00\x00', loginReq, msgLen)
        pubkey = self.load_publickey("public.key")
        RSAcipher = PKCS1_OAEP.new(pubkey)
        etk = RSAcipher.encrypt(tk)
        return msg + etk, tk

    def encryptLoginResp(self, payload, tk):
        loginRes, rand = self.createLoginRes(payload)
        msgLen = 12 + len(loginRes) + 16
        response = self.encriptAndAuth(tk, b'\x00\x10', loginRes, msgLen)
        return response, rand

    def createLoginReq(self, username, password):
        rand = Random.get_random_bytes(16).hex()
        loginReq = str(time.time_ns()) + '\n' + username + '\n' + password + '\n' + rand
        self.loginHash = self.getHash(loginReq.encode("utf-8"))
        return loginReq, rand #type: str

    def createLoginRes(self, recievedPayloadStr):
        rand = Random.get_random_bytes(16).hex()
        strResponse = self.getHash(recievedPayloadStr) + '\n' + rand #type: str
        return strResponse.encode("utf-8"), rand # request hash + random bytes,


    def getHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        return h.hexdigest()