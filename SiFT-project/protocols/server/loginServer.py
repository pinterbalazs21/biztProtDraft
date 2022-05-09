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
        login_res = self.__create_login_response(payload)
        respone_hash = bytes.fromhex(login_res[0:64].decode("utf-8"))
        rand = login_res[65:]
        msg_len = 12 + len(login_res) + 16
        response = self.MTP.encrypt_and_auth(b'\x00\x10', login_res, msg_len, tk)
        return response, respone_hash, rand

    def __create_login_response(self, received_payload_str):
        rand = Random.get_random_bytes(16).hex()
        str_response = get_hash(received_payload_str) + "\n" + rand  # type: str
        return str_response.encode("utf-8")  # request hash + random bytes,

    def __decrypt_login_request(self, raw_msg, keypair):
        # accepts and verifies loginRequests
        # decrypting encrypted temporary key
        etk = raw_msg[-256:]
        rsa_cipher = PKCS1_OAEP.new(keypair)
        tk = rsa_cipher.decrypt(etk)
        # decrypting msg using the tk
        msg = raw_msg[:-256]
        login_req = self.MTP.decrypt_and_verify(msg, tk)
        self.__filter_duplicate(login_req)
        ServerLoginProtocol.loginReqList.append(login_req)
        return login_req, tk

    def __create_final_key(self, ikey, salt):
        print("Final key constructed")
        key = HKDF(ikey, 32, salt, SHA256)
        self.MTP.set_final_key(key)

    def __filter_duplicate(self, req):
        if req in ServerLoginProtocol.loginReqList:
            raise CloseConnectionException("Duplicated request!")

    def __split_login_request(self, login_request):
        data = login_request.decode("utf-8").split("\n")
        time_stamp_str = data[0]
        username = data[1]
        pw = data[2]
        client_random_str = data[3]  # first part of final key
        client_random = client_random_str.encode("utf-8")

        print("-----")
        print("User data from request:")
        print("client random " + client_random_str)
        print("time " + time_stamp_str)
        print("username " + username)
        # print("pw " + pw)
        print("-----")
        return client_random, time_stamp_str, username, pw

    def __check_timestamp(self, timeStampStr, window=1.2E11):
        time_stamp = int(timeStampStr)
        current_time = time.time_ns()
        if not (current_time - window / 2) < time_stamp & time_stamp < (current_time + window / 2):
            raise CloseConnectionException("Wrong timestamp")

    def __create_hash(self, pwd, salt):
        pwdhash = scrypt(pwd, salt, 16, N=2 ** 14, r=8, p=1) # don't believe the warning - salt should be bytes
        return pwdhash

    def __check_user_data(self, username, password):
        with open(self.userdatafile, newline='') as csvfile:
            userdata = csv.reader(csvfile, delimiter=',')
            try:
                for row in userdata:
                    r_username = row[0]
                    r_pwd_hash = bytes.fromhex(row[1])
                    r_salt = bytes.fromhex(row[2])

                    if r_username == username:
                        pwd_hash = self.__create_hash(password, r_salt)
                        if r_pwd_hash != pwd_hash:
                            raise CloseConnectionException('Error: Wrong password')
                        else:
                            return
                raise CloseConnectionException('Username unknown')
            except ValueError as ve:
                print(ve)
                raise CloseConnectionException('Error: Cannot import password from file ' + self.userdatafile)

    def accept_login_request(self, s, keypair):
        header, msg = self.MTP.wait_for_message(s)
        msg_type = header[2:4]
        # login request
        if msg_type == b'\x00\x00':
            login_request, tk = self.__decrypt_login_request(header + msg, keypair)
            client_random, time_stamp_str, username, pwd = self.__split_login_request(login_request)

            self.__check_timestamp(time_stamp_str)  # raises close connection exception in case of issues
            self.__check_user_data(username, pwd)  # raises close connection exception in case of issues

            response, salt, server_random = self.__encrypt_login_response(login_request, tk)
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
