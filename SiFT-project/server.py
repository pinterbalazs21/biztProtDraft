import hashlib
import socket
import threading

import os
import base64

from protocols.mtp import MTP
from Crypto.PublicKey import RSA
from protocols.server.commandsServer import ServerCommandsProtocol
from protocols.server.downloadServer import ServerDownloadProtocol
from protocols.server.loginServer import ServerLoginProtocol

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
        commandHandler = ServerCommandsProtocol(msgHandler)
        downloadHandler = ServerDownloadProtocol(msgHandler)
        # TODO add upload handler when it exists

        with conn:
            print(f"Connected by {addr}")
            # accepts and verifies login request
            # if ok: response, otherwise: close connection
            loginHandler.acceptLoginRequest(conn, self.keypair)

            # waiting for message loop (commands protocol)
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
                    self.__acceptCommandReq(commandHandler, downloadHandler, conn, header + tail)

    # TODO shouldn't this be in the server command protocol?
    # TODO and btw it is quite a spaghetti, it took a while to implement dnl in it
    def __acceptCommandReq(self, commandHandler, downloadHandler, conn, rawMSG):
        """
        Decrypts and verifies request, if ok: execute command otherwise: connection close
        """
        command, args = commandHandler.decryptCommandMsg(rawMSG)
        # args tuple!
        print(command)
        if command == "pwd": # 0 args
            print("command request: pwd")
            try:
                wd = os.getcwd()
                response = commandHandler.encryptCommandRes(command, rawMSG, 'success', wd)
                conn.sendall(response)
            except OSError:
                response = commandHandler.encryptCommandRes(command, rawMSG, 'failure')
                conn.sendall(response)

        elif command == "lst": # 0 args
            print("command request: lst")
            try:
                lstResult = os.listdir()
                lstStr = '\n'.join([str(item) for item in lstResult])
                if not lstStr:#todo empty dir handling itt, ez még nem jó
                    lstStr = ""
                encodedStr = base64.b64encode(lstStr.encode('utf-8')).decode('utf-8')
                response = commandHandler.encryptCommandRes(command, rawMSG, 'success', encodedStr)
                conn.sendall(response)
                print("Sending success")
            except OSError:
                response = commandHandler.encryptCommandRes(command, rawMSG, 'failure', "OSError")
                conn.sendall(response)

        elif command == "chd": # 1 args
            print("command request: chd")
            try:
                os.chdir(args[0])
                response = commandHandler.encryptCommandRes(command, rawMSG, 'success')
                conn.sendall(response)
            except OSError:
                response = commandHandler.encryptCommandRes(command, rawMSG, 'failure', "OSError occured")
                conn.sendall(response)

        #TODO root directory for user
        elif command == "mkd": # 1 args
            print("command request: mkd")
            try:
                if args[0].startswith('..') or args[0].startswith('\..') or args[0].startswith('/..'):# todo lehet contains jobb egyszerubb volna
                    raise Exception('Nice try')
                path = os.path.join(os.getcwd(), args[0])
                #todo: path names may be supported by implementations, but this is not mandatory
                #todo: Implementations should pay attantion to prevent creating a new directory
                #outside of the root directory associated with the currently logged in user.
                os.mkdir(path)
                response = commandHandler.encryptCommandRes(command, rawMSG, 'success')
                conn.sendall(response)
            except Exception as error:#todo OSError?
                print(type(error))
                response = commandHandler.encryptCommandRes(command, rawMSG, 'failure', str(error))
                conn.sendall(response)

        # TODO HOW? Implementations should pay attention to prevent downloading/uploading/deleting a file from a directory outside of the root directory associated with the currently logged in user.
        elif command == "del":  # 1 args
            print("command request: del")
            try:
                path = os.path.join(os.getcwd(), args[0])
                if os.path.exists(path) and os.path.isfile(path):
                    os.remove(path)
                elif os.path.exists(path) and len(os.listdir(path)) == 0:
                    os.rmdir(path)
                else:
                    raise Exception('File or folder does not exist (or not empty)')
                response = commandHandler.encryptCommandRes(command, rawMSG, 'success')
                conn.sendall(response)
            except Exception as error:
                response = commandHandler.encryptCommandRes(command, rawMSG, 'failure', str(error))
                conn.sendall(response)

        # TODO HOW? Implementations should pay attention to prevent downloading/uploading/deleting a file from a directory outside of the root directory associated with the currently logged in user.
        elif command == "upl":  # 3 args
            print("command request: upl")
            #todo
        # TODO HOW? Implementations should pay attention to prevent downloading/uploading/deleting a file from a directory outside of the root directory associated with the currently logged in user.
        elif command == "dnl":  # 1 args
            print("command request: dnl")
            try:
                path = os.path.join(os.getcwd(), args[0])
                if not os.path.exists(path) or not os.path.isfile(path):
                    raise Exception('File does not exist (or it is not a file): ' + path) # TODO any other reasons to reject req?

                fileSize = os.path.getsize(path)
                if(fileSize==0):
                    raise Exception(
                        'File is empty: ' + path)  # TODO any other reasons to reject req?

                # Source of this hashing snippet: https://www.quickprogrammingtips.com/python/how-to-calculate-sha256-hash-of-a-file-in-python.html
                sha256_hash = hashlib.sha256()
                with open(path, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                    fileHash = sha256_hash.hexdigest()

                response = commandHandler.encryptCommandRes(command, rawMSG, 'success', str(fileSize), fileHash)
                conn.sendall(response)
                downloadHandler.executeDownloadProtocol(path, conn)
            except Exception as error:
                if command == "dnl" or command == "upl":
                    response = commandHandler.encryptCommandRes(command, rawMSG, 'reject', str(error))
                else:
                    response = commandHandler.encryptCommandRes(command, rawMSG, 'failure', str(error))

                conn.sendall(response)
            #todo

server = SiFTServer()
server.listenAll()
