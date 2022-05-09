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
        self.host = "localhost" # "10.71.0.167" # TODO put IP of server here
        with open("thyme-public.key", 'rb') as f:
            pubkeystr = f.read()
            self.pubKey = RSA.import_key(pubkeystr)
        with open("private.key", 'rb') as f:
            asd = f.read()
            self.keypair = RSA.import_key(asd)
        print("Server init")

    def __save_pub_key(self, pubkey, pubkeyfile):
        with open(pubkeyfile, 'wb') as f:
            f.write(pubkey.export_key(format='PEM'))

    def listen_all(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # This is here to prevent "Address already in use" errors
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            s.bind((self.host, self.port))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.listen,
                                 args=(conn, addr),
                                 ).start()

    def listen(self, conn, addr):
        msg_handler = MTP()
        login_handler = ServerLoginProtocol(msg_handler)

        with conn:
            try:
                print(f"Connected by {addr}")
                # accepts and verifies login request
                # if ok: response, otherwise: close connection
                login_handler.accept_login_request(conn, self.keypair)
            except CloseConnectionException as ce:
                print("Close Connection Exception caught:")
                print(ce)
                conn.close()
                print("Connection closed, thread terminated")
                return

            command_handler = ServerCommandsProtocol(msg_handler, userRoot=os.getcwd())
            download_handler = ServerDownloadProtocol(msg_handler)
            upload_handler = ServerUploadProtocol(msg_handler)
            # waiting for message loop (commands protocol)
            while True:
                try:
                    command, args = command_handler.accept_command_req(conn)
                    command_handler.handle_command_req(command, args, conn, download_handler, upload_handler)
                except CloseConnectionException as ce:
                    print("Close Connection Exception caught:")
                    print(ce)
                    conn.close()
                    print("Connection closed, thread terminated")
                    return


server = SiFTServer()
server.listen_all()
