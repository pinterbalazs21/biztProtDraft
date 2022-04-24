import time
import csv

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.KDF import scrypt

class ServerLoginProtocol:
    def __init__(self, MTP):
        self.loginHash = ''
        self.MTP = MTP
        '''
        csv file with username-pwdhash pairs
        '''
        self.userdatafile = 'userdata.csv'

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
        clientRandomStr = data[3]  # first part of final key
        clientRandom = clientRandomStr.encode("utf-8")

        print("-----")
        print("User data from request:")
        print("client random " + clientRandomStr)
        print("time " + timeStampStr)
        print("username " + username)
        print("pw " + pw)  # TODO we probably shouldn't print this, for DEBUG only
        print("-----")
        return (clientRandom, timeStampStr, username, pw)

    # todo ez mehetne MTP-be checknél?
    def __checkTimestamp(self, timeStampStr, window=2E9):
        timeStamp = int(timeStampStr)
        currentTime = time.time_ns()
        return (currentTime - window / 2) < timeStamp & timeStamp < (currentTime + window / 2)
        # TODO Preferably, the server should also check if the same request was not received in another connection (with another client) within the acceptance time window around the current time at the server.

    def __createHash(self, pwd, salt):
        pwdhash = scrypt(pwd, salt, 16, N=2 ** 14, r=8, p=1) # don't believe the warning - salt should be bytes
        return pwdhash

    def __checkUserData(self, username, password):
        #return True
        with open(self.userdatafile, newline='') as csvfile:
            userdata = csv.reader(csvfile, delimiter=',')
            try:
                for row in userdata:
                    rUsername = row[0]
                    rPwdHash = bytes.fromhex(row[1])
                    rSalt = bytes.fromhex(row[2])

                    if rUsername == username:
                        pwdHash = self.__createHash(password, rSalt)
                        if rPwdHash != pwdHash:
                            print('Error: Wrong password')
                            return False
                        else:
                            return True
                print('Username unknown')
                return False
            except ValueError as ve:
                print(ve)
                print('Error: Cannot import password from file ' + self.userdatafile)
                return False # TODO erre conn close lesz a reakció, szerintem itt inkább az kéne
                # sys.exit(1)  # TODO itt nem kéne conn.close() kéne?

    def acceptLoginRequest(self, s, keypair):
        header, msg = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        # login request
        if msgType == b'\x00\x00':  # python 3.10 tud már match-case-t (switch case helyett)
            loginRequest, tk = self.__decryptLoginRequest(header + msg, keypair)
            # todo check if this is right:
            if not loginRequest:
                print("No(t) request")
                s.close()
                return

            clientRandom, timeStampStr, username, pwd = self.__splitLoginRequest(loginRequest)

            if not self.__checkTimestamp(timeStampStr):
                print("Wrong timestamp")
                s.close()
                return
            if not self.__checkUserData(username, pwd):  # TODO
                print("Checking user data failed, closing connection")
                s.close()
                return

            # TODO maybe move this into a helper func
            response, salt, server_random = self.__encryptLoginResponse(loginRequest, tk)
            ikey = clientRandom + server_random
            self.__createFinalKey(ikey, salt)
            s.sendall(response)
            print("Login response sent")
        else:
            # todo check if this is right:
            print("Wrong request type (not login request)")
            s.close()
        return
