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

    def __create_final_key(self, ikey, salt):
        print("Final key constructed")
        key = HKDF(ikey, 32, salt, SHA256)
        print(key.hex())
        self.MTP.set_final_key(key)

    def __save_hash(self, payload):
        h = SHA256.new()
        h.update(payload)
        self.loginHash = h.hexdigest()

    def __create_login_request(self, username, password):
        clientRandom = Random.get_random_bytes(16).hex()
        loginPayload = str(time.time_ns()) + "\n" + username + "\n" + password + "\n" + clientRandom

        loginPayload = loginPayload.encode("utf-8")
        clientRandom = clientRandom.encode("utf-8")

        return loginPayload, clientRandom  # type: str

    def __encrypt_login_request(self, loginReq):  # loginReq == payload
        tk = Random.get_random_bytes(32)
        msgLen = 16 + len(loginReq) + 12 + 256  # length of header, (encrypted) payload, auth mac + ETK
        msg = self.MTP.encrypt_and_auth(b'\x00\x00', loginReq, msgLen, tk)
        pubkey = self.__load_publickey()
        RSAcipher = PKCS1_OAEP.new(pubkey)
        etk = RSAcipher.encrypt(tk)
        return msg + etk, tk

    def __decrypt_login_response(self, tk, msg):
        payload = self.MTP.decrypt_and_verify(msg, tk)
        # üzenetben stringként 1 byte == 2 hexa szám-->64 hosszú str
        if self.loginHash != payload[0:64].decode('utf-8'):
            raise CloseConnectionException("Wrong hash value in login response")
        return payload

    def __prompt_user_data(self):
        print("Input username")
        username = input()
        print("Input password")
        pwd = input()
        return username, pwd

    def __receive_connection_confirmation(self, s, client_random, tk):
        header, tail = self.MTP.wait_for_message(s)
        msgType = header[2:4]
        if msgType == b'\x00\x10':
            payload = self.__decrypt_login_response(tk, header + tail)
            server_random = payload[65:]
            # final symmetric key:
            print("salt: ", self.loginHash)
            client_random = bytes.fromhex(client_random.decode("utf-8"))
            server_random = bytes.fromhex(server_random.decode("utf-8"))
            print("client random: ", client_random.hex())
            print("server random: ", server_random.hex())
            ikey = client_random + server_random
            salt = bytes.fromhex(self.loginHash)
            self.__create_final_key(ikey, salt)
            print("Connection established")
            return
        raise CloseConnectionException("Wrong message type: " + msgType + " instead of 00 10")

    def execute_login(self, s):
        """
        Creates login request, sends it, waits for response
        :param s: socket to use when sending and receiving login messages
        """
        username, pwd = self.__prompt_user_data()
        loginPayload, clientRandom = self.__create_login_request(username, pwd)
        encryptedLoginRequest, tk = self.__encrypt_login_request(loginPayload)
        s.sendall(encryptedLoginRequest)
        self.__save_hash(loginPayload)  # the description said to save the hash only after sending the request
        self.__receive_connection_confirmation(s, clientRandom, tk)
