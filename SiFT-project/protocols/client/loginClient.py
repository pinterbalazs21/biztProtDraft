import sys
import time
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA


class ClientLoginProtocol:
    def __init__(self, MTP):
        self.loginHash = ''
        self.MTP = MTP
        self.pubkeyfile = "public.key"

    def __load_publickey(self):
        with open(self.pubkeyfile, 'rb') as f:
            pubkeystr = f.read()
        try:
            return RSA.import_key(pubkeystr)
        except ValueError:
            print('Error: Cannot import public key from file ' + self.pubkeyfile)
            sys.exit(1)

    def __createFinalKey(self, ikey, salt):
        self.MTP.finalKey = HKDF(ikey, 32, salt, SHA256)
        print("Final key constructed:")
        print(self.MTP.finalKey)

    def __saveHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        self.loginHash = h.hexdigest()

    def __createLoginRequest(self, username, password):
        clientRandom = Random.get_random_bytes(16).hex()
        loginPayload = str(time.time_ns()) + '\n' + username + '\n' + password + '\n' + clientRandom

        loginPayload = loginPayload.encode("utf-8")
        clientRandom = clientRandom.encode("utf-8")

        return loginPayload, clientRandom  # type: str

    def __encryptLoginRequest(self, loginReq):  # loginReq == payload
        print("Encrypting login req")
        tk = Random.get_random_bytes(32)
        msgLen = 16 + len(loginReq) + 12 + 256  # length of header, (encrypted) payload, auth mac + ETK
        msg = self.MTP.encryptAndAuth(b'\x00\x00', loginReq, msgLen, tk)
        pubkey = self.__load_publickey()
        RSAcipher = PKCS1_OAEP.new(pubkey)
        etk = RSAcipher.encrypt(tk)
        return msg + etk, tk

    def __decryptLoginResponse(self, tk, msg):
        payload = self.MTP.decryptAndVerify(msg, tk)
        # üzenetben stringként 1 byte == 2 hexa szám-->64 hosszú str
        if self.loginHash != payload[0:64].decode('utf-8'):
            print("Wrong Hash Value")
        return payload

    def __promptUserData(self):
        print("Input username")
        username = input()
        print("Input password")
        pwd = input()
        return username, pwd

    # TODO MTP part of message should be handled by mtp
    def __receiveConnectionConfirmation(self, s, client_random, tk):
        header = s.recv(16)
        MTPdata_size = header[4:6]
        msgType = header[2:4]
        len = int.from_bytes(MTPdata_size, byteorder='big')
        if (len == 0):
            exit(1) # TODO proper error handling
        tail = s.recv(len - 16)
        if msgType == b'\x00\x10':
            payload = self.__decryptLoginResponse(tk, header + tail)
            server_random = payload[65:]
            # final symmetric key:
            ikey = client_random + server_random
            salt = payload[:64]
            self.__createFinalKey(ikey, salt)
            print("Connection established")
            return
        print("something went wrong (wrong message type)")
        # TODO error handling - success or not, close session if not, etc.

    def executeLogin(self, s):
        """
        Creates login request, sends it, waits for response
        :param s: socket to use when sending and receiving login messages
        """
        username, pwd = self.__promptUserData()
        loginPayload, clientRandom = self.__createLoginRequest(username, pwd)
        encryptedLoginRequest, tk = self.__encryptLoginRequest(loginPayload)
        s.sendall(encryptedLoginRequest)
        self.__saveHash(loginPayload) # the description said to save the hash only after sending the request
        self.__receiveConnectionConfirmation(s, clientRandom, tk)