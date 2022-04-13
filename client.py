from socket import RCVALL_SOCKETLEVELONLY
import sys, getopt

from matplotlib.pyplot import rc
from Crypto.Cipher import AES

#debug variables:
#symmetric key: todo establish with MTP protocol
key = b'\x00\x00'

class SiFTClient():

    def __init__(self, port = 5150):
        self.port = port
        self.key = "todoGetKey"
        print("init on port" + str(self.port))

    def pwd(self):
        #Print current working directory
        print("pwd")

    def lst(self):
        #List content of the current working directory
        print("pwd")

    def mkd(self, dirName):
        """
        Make directory: Creates a new directory on the server. 
        The name of the directory to be created is provided as 
        an argument to the mkd command.
        """
        print("mkd " + dirName)
    def delete(self):
        """
        Delete file or directory: Deletes a file or a directory 
        on the server. The name of the file or directory to be 
        deleted is provided as an argument to the del command.
        """
        print("del")

    def upl(self):
        """
        Upload file: Uploads a file from the client to the server. 
        The name of the file to be uploaded is provided as an 
        argument to the upl command and the file is put in the 
        current working directory on the server.
        """
        print("upl")

    def dnl(self, fileName):
        """
        Download file: 
        Downloads a file from the current working directory of the 
        server to the client. The name of the file to be downloaded 
        is provided as an argument to the dnl command.
        """
        print("dnl " + fileName)


class MTP:

    def __init__(self):
        #todo sqn honnan számozva?
        self.sqn = 0
        #self.key #todo ezt valahogy elkérni

    def createHeader(self, typ, msg_length):
        # create header
        header_version = b'\x01\x00' #v1.0
        header_type = typ #2B, 10 possible value. 1st byte: interaction , 2nd byte: 1st nibble: request or response 2nd nibble: sub-types
        header_length = msg_length.to_bytes(2, byteorder='big') #2B, message length in bytes, including header
        header_sqn = (sqn + 1).to_bytes(2, byteorder='big')  #2B next message sequence number (encoded on 4 bytes)
        header_rnd = Random.get_random_bytes(6) #6B, random bytes
        header_rsv = b'\x00\x00'
        return header_version + header_type + header_length + header_sqn + header_rnd + header_rsv

    def decryptAndVerify(self, msg):#nonce: sqn + rnd
        #key global variable, todo
        header = msg[0:16]
        encrypted_payload = msg[16:-12]
        nonce = header[6:14] #sqn:header[6:8], rnd = header[8:14]
        authtag = msg[-12:]
        msg_length = header[4:6]
        header_sqn = header[6:8]
        if len(msg) != int.from_bytes(msg_length, byteorder='big'):
            print("Warning: Message length value in header is wrong!")
            print("Processing is continued nevertheless...")

        rcvsqn = 0 # todo store and update recent sqn 
        print("Expecting sequence number " + str(rcvsqn + 1) + " or larger...")
        sndsqn = int.from_bytes(header_sqn, byteorder='big')
        if (sndsqn <= rcvsqn):
            print("Error: Message sequence number is too old!")
            print("Processing completed.")
            sys.exit(1)    
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

    def encriptAndAuth(self, typ, payload):
        msg_length = 16 + len(payload) + 12 #length of header, (encripted) payload, and auth mac
        header = createHeader(typ, msg_length)
        nonce = header[6:16] #sqn:[6:8], rnd = [8:14]
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=authtag_length)
        AE.update(header)
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)
        return header + encrypted_payload + authtag#msg