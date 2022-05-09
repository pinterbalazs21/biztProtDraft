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
        self.MTP.set_final_key(key)

    def __save_hash(self, payload):
        h = SHA256.new()
        h.update(payload)
        self.loginHash = h.hexdigest()

    def __create_login_request(self, username, password):
        client_random = Random.get_random_bytes(16).hex()
        login_payload = str(time.time_ns()) + "\n" + username + "\n" + password + "\n" + client_random

        login_payload = login_payload.encode("utf-8")
        client_random = client_random.encode("utf-8")

        return login_payload, client_random  # type: str

    def __encrypt_login_request(self, login_req):  # loginReq == payload
        tk = Random.get_random_bytes(32)
        msg_len = 16 + len(login_req) + 12 + 256  # length of header, (encrypted) payload, auth mac + ETK
        msg = self.MTP.encrypt_and_auth(b'\x00\x00', login_req, msg_len, tk)
        pubkey = self.__load_publickey()
        rsa_cipher = PKCS1_OAEP.new(pubkey)
        etk = rsa_cipher.encrypt(tk)
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
        msg_type = header[2:4]
        if msg_type == b'\x00\x10':
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
        raise CloseConnectionException("Wrong message type: " + msg_type + " instead of 00 10")

    def execute_login(self, s):
        """
        Creates login request, sends it, waits for response
        :param s: socket to use when sending and receiving login messages
        """
        username, pwd = self.__prompt_user_data()
        login_payload, client_random = self.__create_login_request(username, pwd)
        encrypted_login_request, tk = self.__encrypt_login_request(login_payload)
        s.sendall(encrypted_login_request)
        self.__save_hash(login_payload)  # the description said to save the hash only after sending the request
        self.__receive_connection_confirmation(s, client_random, tk)
