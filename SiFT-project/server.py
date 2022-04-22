import socket
import threading

from protocols.commands import CommandsProtocol
from protocols.mtp import MTP
from Crypto.PublicKey import RSA
import os

from protocols.server.loginServer import ServerLoginProtocol

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
            # TODO this is here to prevent "Address already in use", not sure, but probably should be deleted when not debugging anymore
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            s.bind((self.host, self.port))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.listen,
                                 args=(conn, addr),
                                 ).start()

    def listen(self, conn, addr):
        msgHandler = MTP()
        loginHandler = ServerLoginProtocol(msgHandler)

        with conn:
            print(f"Connected by {addr}")
            # accepts and verifies login request
            # if ok: response, otherwise: close connection
            loginHandler.acceptLoginRequest(conn, self.keypair)

            # waiting for message loop (commands protocol)
            commandHandler = CommandsProtocol(msgHandler)
            while True:
                #todo
                header = conn.recv(16)
                MTPdata_size = header[4:6]
                msgType = header[2:4]
                len = int.from_bytes(MTPdata_size, byteorder='big')
                if (len == 0):
                    continue
                tail = conn.recv(len - 16)
                if msgType == b'\x01\x00':
                    print("command recieved")
                    self.acceptCommandReq(commandHandler, conn, header + tail)
                print("siuuuu")

    def acceptCommandReq(self, commandHandler, conn, rawMSG):
        """
        Decrypts and verifies request, if ok: execute command otherwise: connection close
        """
        command, args = commandHandler.decryptCommandMsg(rawMSG)
        # args tuple!
        print(command)
        if command == "pwd": # 0 args
            print("command request: pwd")
            #todo failure handling
            response = commandHandler.encryptCommandRes(command, rawMSG, 'success', os.getcwd())
            conn.sendall(response)
            print("command response sent: pwd")
        elif command == "lst": # 0 args
            print("command request: lst")
            response = commandHandler.encryptCommandRes(command, rawMSG, 'success', os.getcwd())
            conn.sendall(response)
            #todo
        elif command == "chd": # 1 args
            print("command request: chd")
            #todo
        elif command == "mkd": # 1 args
            print("command request: mkd")
            #todo
        elif command == "del": # 1 args
            print("command request: del")
            #todo
        elif command == "upl": # 3 args
            print("command request: upl")
            #todo
        elif command == "dnl": # 1 args
            print("command request: dnl")
            #todo

server = SiFTServer()
server.listenAll()
