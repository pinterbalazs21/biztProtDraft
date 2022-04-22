import sys
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import HKDF

class ServerLoginProtocol:
    def __init__(self, MTP):
        self.loginHash = ''
        self.MTP = MTP

    def __load_publickey(self, pubkeyfile):
        with open(pubkeyfile, 'rb') as f:
            pubkeystr = f.read()
        try:
            return RSA.import_key(pubkeystr)
        except ValueError:
            print('Error: Cannot import public key from file ' + pubkeyfile)
            sys.exit(1)

    def __encryptLoginResponse(self, payload, tk):
        print("Encrypting login response")
        loginRes = self.__createLoginResponse(payload)
        hash = loginRes[0:64]
        rand = loginRes[65:]
        msgLen = 12 + len(loginRes) + 16
        response = self.MTP.encryptAndAuth(b'\x00\x10', loginRes, msgLen, tk)
        return response, hash, rand

    def __createLoginResponse(self, receivedPayloadStr):
        rand = Random.get_random_bytes(16).hex()
        strResponse = self.__getHash(receivedPayloadStr) + '\n' + rand  # type: str
        return strResponse.encode("utf-8")  # request hash + random bytes,

    def __decryptLoginRequest(self, rawMSG, keypair):
        # accepts and verifies loginRequests
        # decrypting encrypted temporary key
        etk = rawMSG[-256:]
        RSAcipher = PKCS1_OAEP.new(keypair)
        tk = RSAcipher.decrypt(etk)
        # decrypting msg using the tk
        msg = rawMSG[:-256]
        loginReq = self.MTP.decryptAndVerify(msg, tk)
        return loginReq, tk

    def __getHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        return h.hexdigest()

    def __createFinalKey(self, ikey, salt):
        self.MTP.finalKey = HKDF(ikey, 32, salt, SHA256)
        print("Final key constructed:")
        print(self.MTP.finalKey)

    def __splitLoginRequest(self, loginRequest):
        data = loginRequest.decode("utf-8").splitlines()
        timeStampStr = data[0]
        username = data[1]
        pw = data[2]
        clientRandom = data[3].encode("utf-8")  # first part of final key

        print("client random " + clientRandom.decode("utf-8"))
        print("time " + timeStampStr)
        print("username " + username)
        print("pw " + pw)  # TODO we probably shouldn't print this, for DEBUG only
        return clientRandom, timeStampStr, username, pw

    #todo ez mehetne MTP-be checknél?
    def __checkTimestamp(self, timeStampStr, window = 2E9):
        timeStamp = int(timeStampStr)
        currentTime = time.time_ns()
        return (currentTime - window/2) < timeStamp & timeStamp < (currentTime + window/2)
        # TODO Preferably, the server should also check if the same request was not received in another connection (with another client) within the acceptance time window around the current time at the server.

    def __checkUserData(self, username, pwd):
        return True # TODO

    def acceptLoginRequest(self, conn, keypair):
        header = conn.recv(16)  # header
        MTPdata_size = header[4:6]
        msgType = header[2:4]
        len = int.from_bytes(MTPdata_size, byteorder='big')
        if (len == 0):
            return  # todo connection close?
        tail = conn.recv(len - 16)  # msg_size - header size
        # login request
        if msgType == b'\x00\x00':  # python 3.10 tud már match-case-t (switch case helyett)
            loginRequest, tk = self.__decryptLoginRequest(header + tail, keypair)
            # todo check if this is right:
            if not loginRequest:
                print("No(t) request")
                conn.close()
                return

            clientRandom, timeStampStr, username, pw = self.__splitLoginRequest(loginRequest)

            if not self.__checkTimestamp(timeStampStr):
                print("Wrong timestamp")
                conn.close()
                return
            if not self.__checkUserData(username, pw):  # TODO
                print("Wrong user data")
                conn.close()
                return

            # TODO maybe move this into a helper func
            response, salt, server_random = self.__encryptLoginResponse(loginRequest, tk)
            ikey = clientRandom + server_random
            self.__createFinalKey(ikey, salt)
            conn.sendall(response)
            print("Login response sent")
        else:
            # todo check if this is right:
            print("Wrong request type (not login request)")
            conn.close()
        return