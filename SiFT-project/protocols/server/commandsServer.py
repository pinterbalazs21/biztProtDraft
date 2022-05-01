from Crypto.Hash import SHA256

from protocols.common.utils import *
import os
import base64

class ServerCommandsProtocol:
    def __init__(self, MTP, userRoot):
        self.userRoot = userRoot
        self.currentWD = userRoot
        self.MTP = MTP

    # creates command response body
    def __createCommandRes(self, type, *args):
        response = type + "\n" + self.latestHash
        if args:# has at least 1 param
            for resp in args:
                response = response + "\n" + resp
        return response.encode("utf-8")

    def encryptCommandRes(self, s,  commandType, *args):
        payload = self.__createCommandRes(commandType, *args)
        response = self.MTP.encryptAndAuth(b'\x01\x10', payload)
        s.sendall(response)

    def decryptCommandMsg(self, rawMSG):
        decryptedPayload = self.MTP.decryptAndVerify(rawMSG).decode("utf-8")
        commandList = decryptedPayload.splitlines()
        commandTypeStr = commandList[0]
        args = ()
        if len(commandList) > 1:
            args = commandList[1:]
        return commandTypeStr, args

    def acceptCommandReq(self, s):
        header, msg = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        if msgType != b'\x01\x00':
            print("Wrong message type")
            s.close()
            return
        rawMSG = header + msg
        self.latestHash = getHash(rawMSG)
        command, args = self.decryptCommandMsg(rawMSG)
        return command, args


    def handleCommandReq(self, command, args, conn, downloadHandler, uploadHandler):
        """
        Decrypts and verifies request, if ok: execute command otherwise: connection close
        """
        # args tuple!
        if command == "pwd": # 0 args
            print("command request: pwd")
            try:
                self.encryptCommandRes(conn, command, 'success', self.currentWD)
            except Exception as error:
                self.encryptCommandRes(conn, command, 'failure', str(error))
        elif command == "lst": # 0 args
            print("command request: lst")
            try:
                if not checkDir(self.userRoot, self.currentWD):
                    raise Exception('Access denied!')#not possible to reach this
                lstResult = os.listdir(self.currentWD)
                lstStr = '\n'.join([str(item) for item in lstResult])
                if not lstStr:#empty dir handling
                    lstStr = ""
                encodedStr = base64.b64encode(lstStr.encode('utf-8')).decode('utf-8')
                self.encryptCommandRes(conn, command, 'success', encodedStr)
                print("Sending success")
            except Exception as error:
                self.encryptCommandRes(conn, command, 'failure', str(error))

        elif command == "chd": # 1 args
            print("command request: chd")
            try:
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                if not checkDir(self.userRoot, path):
                    raise Exception('Access denied! Moving outside the root directory not allowed!')
                if not os.path.exists(path) or os.path.isfile(path):
                    raise Exception('Folder does not exist')
                self.currentWD = path
                self.encryptCommandRes(conn, command, 'success')
            except Exception as error:
                self.encryptCommandRes(conn, command, 'failure', str(error))

        elif command == "mkd":  # 1 args
            print("command request: mkd")
            try:
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                if not checkDir(self.userRoot, path):
                    raise Exception('File is outside root directory of user, access denied')
                os.mkdir(path)
                self.encryptCommandRes(conn, command, 'success')
            except Exception as error:
                self.encryptCommandRes(conn, command, 'failure', str(error))

        elif command == "del":  # 1 args
            print("command request: del")
            try:
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                print(path)
                if not checkDir(self.userRoot, path):
                    raise Exception('File is outside root directory of user, access denied')

                if os.path.exists(path) and os.path.isfile(path):
                    os.remove(path)
                elif os.path.exists(path) and len(os.listdir(path)) == 0:
                    os.rmdir(path)
                else:
                    raise Exception('File or folder does not exist (or not empty)')
                self.encryptCommandRes(conn, command, 'success')
                print("Success-_---------")
            except Exception as error:
                print("Exception" + str(error))
                self.encryptCommandRes(conn, command, 'failure', str(error))

        elif command == "upl":  # 3 args
            try:
                print("command request: upl")
                size = int(args[1])#todo ezekkel semmit nem kell csinálni
                hash = args[2]
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                if not checkDir(self.userRoot, path):
                    raise Exception('File is outside root directory of user, access denied')
                if os.path.isfile(path):
                    raise Exception('File with the name "' + path + '" already exists!')
                print("File will be uploaded to: ", path)
                self.encryptCommandRes(conn, command, 'accept')
                uploadHandler.executeUploadProtocol(path, conn)
            except Exception as error:
                print("Exception" + str(error))
                self.encryptCommandRes(conn, command, 'reject', str(error))

        elif command == "dnl":  # 1 args
            print("command request: dnl")
            try:
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                if not checkDir(self.userRoot, path):
                    raise Exception('File is outside root directory of user, access denied')
                print(path)
                print("File will be downloaded from: ", path)
                if os.path.exists(path) and os.path.isfile(path):
                    fileHash, size = getFileInfo(path)
                    print("file size = " + str(size))
                    if size == 0:
                        raise Exception('File is empty')
                    self.encryptCommandRes(conn, command, 'accept', str(size), fileHash)
                    downloadHandler.executeDownloadProtocol(path, conn)
                else:
                    print("Exception, file does not exist")
                    raise Exception('File does not exist')
            except Exception as error:
                self.encryptCommandRes(conn, command, 'reject', str(error))