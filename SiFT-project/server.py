import socket
import time

from MTP import MTP
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


key = b'0123456789abcdef0123456789abcdef'
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

    def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            conn, addr = s.accept()
            msgHandler = MTP()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    header = conn.recv(16)
                    MTPdata_size = header[4:6]
                    msgType = header[2:4]
                    len = int.from_bytes(MTPdata_size, byteorder='big')
                    if(len == 0):
                        continue
                    tail = conn.recv(len - 16)  # msg_size - header size
                    # login request
                    if msgType == b'\x00\x00': #python 3.10 tud már match-case-t (switch case helyett)
                        logReq, tk = self.acceptLoginReqest(header + tail, msgHandler)
                        #todo close connection in case of failed verification
                        data = logReq.decode("utf-8").splitlines()
                        timeStampStr = data[0]
                        name = data[1]
                        pw = data[2]
                        client_random = data[3].encode("utf-8")#first part of final key
                        print(client_random)
                        print("Time: " + timeStampStr)
                        print("name " + name)
                        print("pw " + pw)
                        if not self.checkTimeTreshold(timeStampStr):
                            print("Wrong timestamp")
                            conn.close()
                            break
                        #todo handle multiple clients
                        #todo password hashing check
                        if not logReq:
                            break
                        response, server_random = msgHandler.encryptLoginResp(logReq, tk)
                        server_random = server_random.encode("utf-8")
                        print("server_random")
                        print(server_random)
                        conn.sendall(response)


                    #payload = self.acceptLoginReqest(header + tail)
                    #if not payload:
                    #    break
                    #conn.sendall(payload)

    def acceptLoginReqest(self, rawMSG, msgHandler):
        #decripting encrypted temporary key
        etk = rawMSG[-256:]
        RSAcipher = PKCS1_OAEP.new(self.keypair)
        tk = RSAcipher.decrypt(etk)
        #decripting msg using the tk
        msg = rawMSG[:-256]
        loginReq = msgHandler.decryptAndVerify(tk, msg)
        return loginReq, tk


    def checkTimeTreshold(self, timeStampStr, window = 2E9):
        timeStamp = int(timeStampStr)
        currentTime = time.time_ns()
        return (currentTime - window/2) < timeStamp & timeStamp < (currentTime + window/2)

server = SiFTServer()
server.listen()
