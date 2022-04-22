import sys
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import HKDF


class MTP:
    def __init__(self):
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

    def decryptAndVerify(self,msg, key = None):#nonce: sqn + rnd
        if key is None:
            key = self.finalKey
        header = msg[0:16]
        encrypted_payload = msg[16:-12]
        nonce = header[6:14] #sqn:header[6:8], rnd = header[8:14]
        authtag = msg[-12:]
        msg_length = header[4:6]
        header_sqn = header[6:8]
        if len(msg) != int.from_bytes(msg_length, byteorder='big'):
            print("Warning: Message length value in header is wrong!")
            print("Processing is continued nevertheless...")

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

    def encriptAndAuth(self, typ, payload, msg_length = 0, key = None):
        # = 0, = None: derived default values
        if key is None:
            key = self.finalKey
        if msg_length == 0:
            msg_length = 12 + len(payload) + 16
        header = self.createHeader(typ, msg_length)#todo sqn MTPselfben tárolni vagy máshol?
        nonce = header[6:14] #sqn:[6:8], rnd = [8:14]
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header)
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)
        self.sqn += 1
        return header + encrypted_payload + authtag#msg


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
        msg = self.MTP.encriptAndAuth(b'\x00\x00', loginReq, msgLen, tk)
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
        response = self.MTP.encriptAndAuth(b'\x00\x10', loginRes, msgLen, tk)
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


class CommandsProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    #creates command request body
    # type can be: 'pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl'
    def createCommandReq(self, type, *args):
        #todo type check or different function for each command
        request = type
        if args:# has at least 1 param
            for parameter in args:
                request = request + "\n" + parameter
        return request.encode("utf-8")

    #creates command response body
    def createCommandRes(self, type, requestPayload, *args):
        response = type + "\n" + self.getHash(requestPayload)
        if args:# has at least 1 param
            for resp in args:
                response = response + "\n" + resp
        return response.encode("utf-8")

    def encryptCommandReq(self, commandType, *args):
        payload = self.createCommandReq(commandType, *args)
        return self.MTP.encriptAndAuth(b'\x01\x00', payload)

    def encryptCommandRes(self, commandType, requestPayload, *args):
        payload = self.createCommandRes(commandType, requestPayload, *args)
        return self.MTP.encriptAndAuth(b'\x01\x10', payload)

    def decryptCommandMsg(self, rawMSG):
        #todo type verification and exception? (b'\x01\x10' or b'\x01\x00')
        decryptedPayload = self.MTP.decryptAndVerify(rawMSG).decode("utf-8")
        commandList = decryptedPayload.splitlines()
        commandTypeStr = commandList[0]
        args = ()
        if len(commandList) > 1:
            args = commandList[1:]
        return commandTypeStr, args

    def getHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        return h.hexdigest()