import hashlib
import socket
import threading

import os
import base64

from protocols.common.utils import getHash, getFileInfo
from protocols.mtp import MTP
from Crypto.PublicKey import RSA
from protocols.server.commandsServer import ServerCommandsProtocol
from protocols.server.downloadServer import ServerDownloadProtocol
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
        commandHandler = ServerCommandsProtocol(msgHandler)
        downloadHandler = ServerDownloadProtocol(msgHandler)
        uploadHandler = ServerUploadProtocol(msgHandler)

        with conn:
            print(f"Connected by {addr}")
            # accepts and verifies login request
            # if ok: response, otherwise: close connection
            loginHandler.acceptLoginRequest(conn, self.keypair)

            # waiting for message loop (commands protocol)
            while True:
                #try:
                command, args = commandHandler.acceptCommandReq(conn)
                self.__handleCommandReq(command, args, conn, commandHandler, downloadHandler, uploadHandler)
                #except Exception as e:
                #    print("Connection closed, thread terminated")
                #    return

    def __handleCommandReq(self, command, args, conn, commandHandler, downloadHandler, uploadHandler):
        """
        Decrypts and verifies request, if ok: execute command otherwise: connection close
        """
        # args tuple!
        if command == "pwd": # 0 args
            print("command request: pwd")
            try:
                wd = os.getcwd()
                commandHandler.encryptCommandRes(conn, command, 'success', wd)
            except Exception as error:
                commandHandler.encryptCommandRes(conn, command, 'failure', str(error))
        elif command == "lst": # 0 args
            print("command request: lst")
            try:
                lstResult = os.listdir()
                lstStr = '\n'.join([str(item) for item in lstResult])
                if not lstStr:#empty dir handling
                    lstStr = ""
                encodedStr = base64.b64encode(lstStr.encode('utf-8')).decode('utf-8')
                commandHandler.encryptCommandRes(conn, command, 'success', encodedStr)
                print("Sending success")
            except Exception as error:
                commandHandler.encryptCommandRes(conn, command, 'failure', str(error))

        elif command == "chd": # 1 args
            print("command request: chd")
            try:
                os.chdir(args[0])
                commandHandler.encryptCommandRes(conn, command, 'success')
            except Exception as error:
                commandHandler.encryptCommandRes(conn, command, 'failure', str(error))

        # TODO root directory for user
        elif command == "mkd":  # 1 args
            print("command request: mkd")
            try:
                path = os.path.join(os.getcwd(), args[0])
                if not self.__checkDir(os.getcwd(), path):  # todo assign root dir to user
                    raise Exception('File is outside root directory of user, access denied')
                os.mkdir(path)
                commandHandler.encryptCommandRes(conn, command, 'success')
            except Exception as error:
                commandHandler.encryptCommandRes(conn, command, 'failure', str(error))

        elif command == "del":  # 1 args
            print("command request: del")
            try:
                path = os.path.join(os.getcwd(), args[0])
                print(path)
                if not self.__checkDir(os.getcwd(), path):  # todo assign root dir to user
                    raise Exception('File is outside root directory of user, access denied')

                if os.path.exists(path) and os.path.isfile(path):
                    os.remove(path)
                elif os.path.exists(path) and len(os.listdir(path)) == 0:
                    os.rmdir(path)
                else:
                    raise Exception('File or folder does not exist (or not empty)')
                commandHandler.encryptCommandRes(conn, command, 'success')
                print("Success-_---------")
            except Exception as error:
                print("Exception" + str(error))
                commandHandler.encryptCommandRes(conn, command, 'failure', str(error))

        elif command == "upl":  # 3 args
            print("command request: upl")
            fileName = args[0]# todo check, if exists: error
            size = int(args[1])
            hash = args[2]

            if not self.__checkDir(os.getcwd(), args[0]):
                raise Exception('File is outside root directory of user, access denied')
            path = os.path.join(os.getcwd(), args[0])
            print("File will be uploaded to: ", path)

            commandHandler.encryptCommandRes(conn, command, 'accept')
            uploadHandler.executeUploadProtocol(path, size, hash, conn)

        elif command == "dnl":  # 1 args
            print("command request: dnl")
            try:
                fileName = args[0]
                if not self.__checkDir(os.getcwd(), args[0]):
                    raise Exception('File is outside root directory of user, access denied')
                path = os.path.join(os.getcwd(), fileName)
                print(path)
                print("File will be downloaded from: ", path)
                if os.path.exists(path) and os.path.isfile(path):
                    fileHash, size = getFileInfo(path)
                    print("file size = " + str(size))
                    if size == 0:
                        raise Exception('File is empty')

                    commandHandler.encryptCommandRes(conn, command, 'accept', str(size), fileHash)
                    downloadHandler.executeDownloadProtocol(path, conn)
                else:
                    print("Exception, file does not exist")
                    raise Exception('File does not exist')
            except Exception as error:
                commandHandler.encryptCommandRes(conn, command, 'reject', str(error))

    def __checkDir(self, root, target):
        root = os.path.abspath(root)
        target = os.path.abspath(target)
        return os.path.commonpath([root]) == os.path.commonpath([root, target])

server = SiFTServer()
server.listenAll()
