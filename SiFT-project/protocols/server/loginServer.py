import time
import csv

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.KDF import scrypt

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import get_hash


class ServerLoginProtocol:
    loginReqList = []

    def __init__(self, MTP):
        self.loginHash = ''
        self.MTP = MTP
        '''
        csv file with username-pwdhash pairs
        '''
        self.userdatafile = 'userdata.csv'

    def __encrypt_login_response(self, payload, tk):
        print("Encrypting login response")
        loginRes = self.__create_login_response(payload)
        hash = bytes.fromhex(loginRes[0:64].decode("utf-8"))
        rand = loginRes[65:]
        msgLen = 12 + len(loginRes) + 16
        response = self.MTP.encrypt_and_auth(b'\x00\x10', loginRes, msgLen, tk)
        return response, hash, rand

    def __create_login_response(self, receivedPayloadStr):
        rand = Random.get_random_bytes(16).hex()
        strResponse = get_hash(receivedPayloadStr) + "\n" + rand  # type: str
        return strResponse.encode("utf-8")  # request hash + random bytes,

    def __decrypt_login_request(self, rawMSG, keypair):
        # accepts and verifies loginRequests
        # decrypting encrypted temporary key
        etk = rawMSG[-256:]
        RSAcipher = PKCS1_OAEP.new(keypair)
        tk = RSAcipher.decrypt(etk)
        # decrypting msg using the tk
        msg = rawMSG[:-256]
        loginReq = self.MTP.decrypt_and_verify(msg, tk)
        self.__filter_duplicate(loginReq)
        ServerLoginProtocol.loginReqList.append(loginReq)
        return loginReq, tk

    def __create_final_key(self, ikey, salt):
        print("Final key constructed:")
        key = HKDF(ikey, 32, salt, SHA256)
        print(key.hex())
        self.MTP.set_final_key(key)

    def __filter_duplicate(self, req):
        if req in ServerLoginProtocol.loginReqList:
            raise CloseConnectionException("Duplicated request!")

    def __split_login_request(self, loginRequest):
        data = loginRequest.decode("utf-8").split("\n")
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

    def __check_timestamp(self, timeStampStr, window=1.2E11):
        print("0000000000000000000000000")
        print(timeStampStr)
        timeStamp = int(timeStampStr)
        currentTime = time.time_ns()
        if not (currentTime - window / 2) < timeStamp & timeStamp < (currentTime + window / 2):
            raise CloseConnectionException("Wrong timestamp")

    def __create_hash(self, pwd, salt):
        pwdhash = scrypt(pwd, salt, 16, N=2 ** 14, r=8, p=1) # don't believe the warning - salt should be bytes
        return pwdhash

    def __check_user_data(self, username, password):
        with open(self.userdatafile, newline='') as csvfile:
            userdata = csv.reader(csvfile, delimiter=',')
            try:
                for row in userdata:
                    rUsername = row[0]
                    rPwdHash = bytes.fromhex(row[1])
                    rSalt = bytes.fromhex(row[2])

                    if rUsername == username:
                        pwdHash = self.__create_hash(password, rSalt)
                        if rPwdHash != pwdHash:
                            raise CloseConnectionException('Error: Wrong password')
                        else:
                            return
                raise CloseConnectionException('Username unknown')
            except ValueError as ve:
                print(ve)
                raise CloseConnectionException('Error: Cannot import password from file ' + self.userdatafile)

    def accept_login_request(self, s, keypair):
        header, msg = self.MTP.wait_for_message(s)
        msgType = header[2:4]
        # login request
        if msgType == b'\x00\x00':
            loginRequest, tk = self.__decrypt_login_request(header + msg, keypair)
            client_random, timeStampStr, username, pwd = self.__split_login_request(loginRequest)

            self.__check_timestamp(timeStampStr) # raises close connection exception in case of issues
            self.__check_user_data(username, pwd) # raises close connection exception in case of issues

            response, salt, server_random = self.__encrypt_login_response(loginRequest, tk)
            client_random = bytes.fromhex(client_random.decode("utf-8"))
            server_random = bytes.fromhex(server_random.decode("utf-8"))
            ikey = client_random + server_random
            print("salt: ", salt)
            print("client random: ", client_random.hex())
            print("server random: ", server_random.hex())
            self.__create_final_key(ikey, salt)
            s.sendall(response)
            print("Login response sent")
        else:
            raise CloseConnectionException("Wrong request type (not login request)")
        return
