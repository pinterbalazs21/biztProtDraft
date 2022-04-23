import sys
from Crypto.Cipher import AES
from Crypto import Random

class MTP:
    def __init__(self):
        self.sqn = 1
        self.rcvsqn = 0
        self.finalKey = None
        print('MTP_INIT')

    def setFinalKey(self, finalKey):
        print("MTP final key set")
        self.finalKey = finalKey

    def createHeader(self, typ, msg_length):
        # create header
        header_version = b'\x01\x00'  # v1.0
        header_type = typ  # 2B, 10 possible value. 1st byte: interaction , 2nd byte: 1st nibble: request or response 2nd nibble: sub-types
        header_length = msg_length.to_bytes(2, byteorder='big') # 2B, message length in bytes, including header
        header_sqn = (self.sqn + 1).to_bytes(2, byteorder='big')  # 2B next message sequence number (encoded on 4 bytes)
        header_rnd = Random.get_random_bytes(6)  # 6B, random bytes
        header_rsv = b'\x00\x00'
        return header_version + header_type + header_length + header_sqn + header_rnd + header_rsv

    def decryptAndVerify(self, msg, key=None): # nonce: sqn + rnd
        if key is None:
            key = self.finalKey
        header = msg[0:16]
        encrypted_payload = msg[16:-12]
        nonce = header[6:14]  # sqn:header[6:8], rnd = header[8:14]
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

    def encryptAndAuth(self, typ, payload, msg_length = 0, key = None):
        """
        Encryption and authentication service of MTP
        :param typ: 2 byte message type field (see protocol description)
        :param msg_length: length of the entire message, including header, in bytes, in big endian
        :return: encrypted message
        """
        # = 0, = None: derived default values
        if key is None:
            key = self.finalKey
        # TODO Document that msg_length works like that!!
        # TODO and on the other hand, why is there a parameter called msg_length, when should I even use that, if this part calculates the msg length for me? shouldn't THAT case be handled as the separated special case?
        if msg_length == 0:
            msg_length = 12 + len(payload) + 16
        header = self.createHeader(typ, msg_length)#todo sqn MTPselfben tárolni vagy máshol?
        nonce = header[6:14] #sqn:[6:8], rnd = [8:14]
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header)
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)
        self.sqn += 1
        return header + encrypted_payload + authtag # msg