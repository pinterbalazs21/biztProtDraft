import socket
import time
import threading
from MTP import MTP, LoginProtocol
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class SiFTServer:
    def __init__(self, port=5150):
        self.port = port
        self.host = "localhost"
        #generating public and private key
        self.keypair = RSA.generate(2048)
        self.pubKey = self.keypair.public_key()
        self.savePubKey(self.pubKey, "public.key")
        print("Server init")

    def savePubKey(self, pubkey, pubkeyfile):
        with open(pubkeyfile, 'wb') as f:
            f.write(pubkey.export_key(format='PEM'))

    def listenAll(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.listen,
                                 args=(conn, addr),
                                 ).start()

    def listen(self, conn, addr):
        msgHandler = MTP()
        with conn:
            print(f"Connected by {addr}")
            #accepts and verifies login request
            #if ok: response, otherwise: close connection
            self.acceptLoginReq(LoginProtocol(msgHandler), conn)
            #waiting for message loop
            while True:
                #todo
                header = conn.recv(16)
                MTPdata_size = header[4:6]
                msgType = header[2:4]
                len = int.from_bytes(MTPdata_size, byteorder='big')
                if (len == 0):
                    continue
                tail = conn.recv(len - 16)
                print("siuuuu")

    def acceptLoginReq(self, loginHandler, conn):
        header = conn.recv(16)  # header
        MTPdata_size = header[4:6]
        msgType = header[2:4]
        len = int.from_bytes(MTPdata_size, byteorder='big')
        if (len == 0):
            return#todo connection close?
        tail = conn.recv(len - 16)  # msg_size - header size
        # login request
        if msgType == b'\x00\x00':  # python 3.10 tud már match-case-t (switch case helyett)
            logReq, tk = loginHandler.decryptLoginReqest(header + tail, self.keypair)
            # todo close connection in case of failed verification
            data = logReq.decode("utf-8").splitlines()
            timeStampStr = data[0]
            name = data[1]
            pw = data[2]
            client_random = data[3].encode("utf-8")  # first part of final key
            print(client_random)
            print("Time: " + timeStampStr)
            print("name " + name)
            print("pw " + pw)
            if not self.checkTimeTreshold(timeStampStr):
                print("Wrong timestamp")
                conn.close()
                return
            # todo password hashing check
            if not logReq:
                return
            response, salt, server_random = loginHandler.encryptLoginResp(logReq, tk)
            ikey = client_random + server_random
            loginHandler.createFinalKey(ikey, salt)
            conn.sendall(response)
            print()

    def checkTimeTreshold(self, timeStampStr, window = 2E9):
        timeStamp = int(timeStampStr)
        currentTime = time.time_ns()
        return (currentTime - window/2) < timeStamp & timeStamp < (currentTime + window/2)

server = SiFTServer()
server.listenAll()
