import base64
import os
from Crypto.Hash import SHA256

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import getFileInfo


class ClientCommandsProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    # creates command request body
    # type can be: 'pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl'
    def __createCommandReq(self, type, *args):
        request = type
        if args:  # has at least 1 param
            for parameter in args:
                request = request + "\n" + str(parameter)
        return request.encode("utf-8")

    def __encryptCommandReq(self, commandType, *args):
        payload = self.__createCommandReq(commandType, *args)
        return self.MTP.encryptAndAuth(b'\x01\x00', payload), payload

    def __saveHash(self, msg):
        print("payload: ", msg)
        print("payload hex: ", msg.hex())
        h = SHA256.new()
        h.update(msg)
        self.latestHash = h.hexdigest()

    def sendPWDReq(self, s):
        msg, payload = self.__encryptCommandReq("pwd")
        s.sendall(msg)
        self.__saveHash(payload)

    def sendLSTReq(self, s):
        msg, payload = self.__encryptCommandReq("lst")
        s.sendall(msg)
        self.__saveHash(payload)

    def sendCHDReq(self, s, dir):
        msg, payload = self.__encryptCommandReq("chd", dir)
        s.sendall(msg)
        self.__saveHash(payload)

    def sendMKDReq(self, s, folderName):
        msg, payload = self.__encryptCommandReq("mkd", folderName)
        s.sendall(msg)
        self.__saveHash(payload)

    def sendDELReq(self, s, fName):
        msg, payload = self.__encryptCommandReq("del", fName)
        s.sendall(msg)
        self.__saveHash(payload)

    def sendUPLReq(self, s, fName):
        fileHash, fileSize = getFileInfo(fName)
        msg, payload = self.__encryptCommandReq("upl", os.path.basename(fName), fileSize, fileHash)
        s.sendall(msg)
        self.__saveHash(payload)

    def sendDNLReq(self, s, fName):
        msg, payload = self.__encryptCommandReq("dnl", fName)
        s.sendall(msg)
        self.__saveHash(payload)

    def __decryptCommandResponseMsg(self, rawMSG):
        decryptedPayload = self.MTP.decryptAndVerify(rawMSG).decode("utf-8")
        commandList = decryptedPayload.split("\n")
        commandTypeStr = commandList[0]
        args = ()
        if len(commandList) > 1:
            args = commandList[1:]
        return commandTypeStr, args

    def waitForCommandResponse(self, s):
        header, msg = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        if msgType != b'\x01\x10':
            raise CloseConnectionException("Wrong message type: " + msgType + " instead of 01 10")
        command, args = self.__decryptCommandResponseMsg(header + msg)
        print("hash: ", args[0])
        print("latest hash: ", self.latestHash)
        if self.latestHash != args[0]:
            raise CloseConnectionException("Wrong hash in command response")
        commandsToFail = ['pwd', 'lst', 'chd', 'mkd', 'del']
        commandsToReject = ['upl', 'dnl']
        if command in commandsToReject:
            if args[1] == 'reject':
                print("command " + command + " rejected: " + args[2])
                return False
            elif args[1] == 'accept':
                self.__printResult(command, *args)
                return True
        elif command in commandsToFail:
            if args[1] == 'failure':
                print("command " + command + " failed: " + args[2])
                return False
            elif args[1] == 'success':
                self.__printResult(command, *args)
                return True
        else:
            raise CloseConnectionException("Command in command response unknown: " + command)

    def __printResult(self, command, *args):
        if command == "pwd":
            print(args[2])
        elif command == "lst":
            if len(args) < 3:  # empty dir handling
                print("")
                return
            encodedLst = args[2]
            decodedBytes = base64.b64decode(encodedLst.encode('utf-8'))
            print(decodedBytes.decode("utf-8"))
        elif command == "dnl":
            self.latestFilesize = args[2]
            self.latestFilehash = args[3]
            print("Hash of the file to be downloaded is: ", self.latestFilesize)
            print("Size of the file to be downloaded is: ", self.latestFilehash)

    def commandHandling(self, rawCommmand, s, downloadHandler, uploadHandler):
        command = rawCommmand.split()[0]
        if command == 'pwd' and len(rawCommmand.split()) == 1:
            self.sendPWDReq(s)
            self.waitForCommandResponse(s)
        elif command == 'lst' and len(rawCommmand.split()) == 1:
            self.sendLSTReq(s)
            self.waitForCommandResponse(s)
        elif command == 'chd' and len(rawCommmand.split()) == 2:
            self.sendCHDReq(s, rawCommmand.split()[1])
            self.waitForCommandResponse(s)
        elif command == 'mkd' and len(rawCommmand.split()) == 2:
            self.sendMKDReq(s, rawCommmand.split()[1])
            self.waitForCommandResponse(s)
        elif command == 'del' and len(rawCommmand.split()) == 2:
            self.sendDELReq(s, rawCommmand.split()[1])
            self.waitForCommandResponse(s)
        elif command == 'upl' and len(rawCommmand.split()) == 2:
            fileName = rawCommmand.split()[1]
            if not os.path.isfile(fileName):
                print("file not found")
                return
            self.sendUPLReq(s, rawCommmand.split()[1])
            if self.waitForCommandResponse(s):
                uploadHandler.executeUploadProtocol(fileName, s)
        elif command == 'dnl' and len(rawCommmand.split()) == 2:
            fileName = rawCommmand.split()[1]
            self.sendDNLReq(s, fileName)
            if self.waitForCommandResponse(s):
                downloadHandler.executeDownloadProtocol(fileName, self.latestFilehash, s)
        else:
            print("Please enter a valid command")