import time
import csv

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.KDF import scrypt

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import getHash


class ServerLoginProtocol:
    loginReqList = []

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
        strResponse = getHash(receivedPayloadStr) + '\n' + rand  # type: str
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
        self.__filterDuplicate(loginReq)
        ServerLoginProtocol.loginReqList.append(loginReq)
        return loginReq, tk

    def __createFinalKey(self, ikey, salt):
        print("Final key constructed:")
        key = HKDF(ikey, 32, salt, SHA256)
        self.MTP.setFinalKey(key)

    def __filterDuplicate(self, req):
        if req in ServerLoginProtocol.loginReqList:
            raise CloseConnectionException("Duplicated request!")

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
        # print("pw " + pw)
        print("-----")
        return (clientRandom, timeStampStr, username, pw)

    def __checkTimestamp(self, timeStampStr, window=2E9):
        timeStamp = int(timeStampStr)
        currentTime = time.time_ns()
        if not (currentTime - window / 2) < timeStamp & timeStamp < (currentTime + window / 2):
            raise CloseConnectionException("Wrong timestamp")

    def __createHash(self, pwd, salt):
        pwdhash = scrypt(pwd, salt, 16, N=2 ** 14, r=8, p=1) # don't believe the warning - salt should be bytes
        return pwdhash

    def __checkUserData(self, username, password):
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
                            raise CloseConnectionException('Error: Wrong password')
                        else:
                            return
                raise CloseConnectionException('Username unknown')
            except ValueError as ve:
                print(ve)
                raise CloseConnectionException('Error: Cannot import password from file ' + self.userdatafile)

    def acceptLoginRequest(self, s, keypair):
        header, msg = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        # login request
        if msgType == b'\x00\x00':
            loginRequest, tk = self.__decryptLoginRequest(header + msg, keypair)
            clientRandom, timeStampStr, username, pwd = self.__splitLoginRequest(loginRequest)

            self.__checkTimestamp(timeStampStr) # raises close connection exception in case of issues
            self.__checkUserData(username, pwd) # raises close connection exception in case of issues

            response, salt, server_random = self.__encryptLoginResponse(loginRequest, tk)
            ikey = clientRandom + server_random
            self.__createFinalKey(ikey, salt)
            s.sendall(response)
            print("Login response sent")
        else:
            raise CloseConnectionException("Wrong request type (not login request)")
        return
