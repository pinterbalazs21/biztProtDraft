import socket
import threading

import os

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.mtp import MTP
from Crypto.PublicKey import RSA
from protocols.server.commandsServer import ServerCommandsProtocol
from protocols.server.loginServer import ServerLoginProtocol
from protocols.server.downloadServer import ServerDownloadProtocol
from protocols.server.uploadServer import ServerUploadProtocol


class SiFTServer:
    def __init__(self, port=5150):
        self.port = port
        self.host = "localhost"
        #generating public and private key
        self.keypair = RSA.generate(2048)
        self.pubKey = self.keypair.public_key()
        self.__savePubKey(self.pubKey, "public.key")
        print("Server init")

    def __savePubKey(self, pubkey, pubkeyfile):
        with open(pubkeyfile, 'wb') as f:
            f.write(pubkey.export_key(format='PEM'))

    def listenAll(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # TODO this is here to prevent "Address already in use" errors, not sure, but probably should be deleted when not debugging anymore
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
            try:
                print(f"Connected by {addr}")
                # accepts and verifies login request
                # if ok: response, otherwise: close connection
                loginHandler.acceptLoginRequest(conn, self.keypair)
            except CloseConnectionException as ce:
                print("Close Connection Exception caught:")
                print(ce)
                conn.close()
                print("Connection closed, thread terminated")
                return

            commandHandler = ServerCommandsProtocol(msgHandler, userRoot = os.getcwd())
            downloadHandler = ServerDownloadProtocol(msgHandler)
            uploadHandler = ServerUploadProtocol(msgHandler)
            # waiting for message loop (commands protocol)
            while True:
                try:
                    command, args = commandHandler.acceptCommandReq(conn)
                    self.__handleCommandReq(command, args, conn, commandHandler, downloadHandler, uploadHandler)
                except CloseConnectionException as ce:
                    print("Close Connection Exception caught:")
                    print(ce)
                    conn.close()
                    print("Connection closed, thread terminated")
                    return

server = SiFTServer()
server.listenAll()
