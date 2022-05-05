import time
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA

from protocols.common.closeConnectionException import CloseConnectionException


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
            raise CloseConnectionException('Error: Cannot import public key from file ' + self.pubkeyfile)

    def __createFinalKey(self, ikey, salt):
        print("Final key constructed")
        key = HKDF(ikey, 32, salt, SHA256)
        self.MTP.setFinalKey(key)

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
            raise CloseConnectionException("Wrong hash value in login response")
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
            raise CloseConnectionException("Length of connection confirmation is 0")
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
        raise CloseConnectionException("Wrong message type (msgType " + msgType + " instead of 00 10")

    def executeLogin(self, s):
        """
        Creates login request, sends it, waits for response
        :param s: socket to use when sending and receiving login messages
        """
        username, pwd = self.__promptUserData()
        loginPayload, clientRandom = self.__createLoginRequest(username, pwd)
        encryptedLoginRequest, tk = self.__encryptLoginRequest(loginPayload)
        s.sendall(encryptedLoginRequest)
        self.__saveHash(loginPayload)  # the description said to save the hash only after sending the request
        self.__receiveConnectionConfirmation(s, clientRandom, tk)
