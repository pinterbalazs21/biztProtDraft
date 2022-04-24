import base64

from Crypto.Hash import SHA256


class ClientCommandsProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    #creates command request body
    # type can be: 'pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl'
    def __createCommandReq(self, type, *args):
        #todo type check or different function for each command
        request = type
        if args:# has at least 1 param
            for parameter in args:
                request = request + "\n" + parameter
        return request.encode("utf-8")

    def __encryptCommandReq(self, commandType, *args):
        payload = self.__createCommandReq(commandType, *args)
        print("payload length: ")
        print(payload)
        print(len(payload))
        return self.MTP.encryptAndAuth(b'\x01\x00', payload)

    def __saveHash(self, msg):
        h = SHA256.new()
        h.update(msg)
        self.latestHash = h.hexdigest()

    def sendPWDReq(self, s):
        msg = self.__encryptCommandReq("pwd")
        s.sendall(msg)
        self.__saveHash(msg)

    def sendLSTReq(self, s):
        msg = self.__encryptCommandReq("lst")
        s.sendall(msg)
        self.__saveHash(msg)

    def sendCHDReq(self, s, dir):
        msg = self.__encryptCommandReq("chd", dir)
        s.sendall(msg)
        self.__saveHash(msg)

    def sendMKDReq(self, s, folderName):
        msg = self.__encryptCommandReq("mkd", folderName)
        s.sendall(msg)
        self.__saveHash(msg)

    def sendDELReq(self, s, fName):
        msg = self.__encryptCommandReq("del", fName)
        s.sendall(msg)
        self.__saveHash(msg)

    def sendUPLReq(self, s, fName):
        msg = self.__encryptCommandReq("upl", fName)
        s.sendall(msg)
        self.__saveHash(msg)

    def sendDNLReq(self, s, fName):
        msg = self.__encryptCommandReq("dnl", fName)
        s.sendall(msg)
        self.__saveHash(msg)

    def __decryptCommandResponseMsg(self, rawMSG):#todo raw msg hash-e kell?
        decryptedPayload = self.MTP.decryptAndVerify(rawMSG).decode("utf-8")
        commandList = decryptedPayload.splitlines()
        commandTypeStr = commandList[0]
        args = ()
        if len(commandList) > 1:
            args = commandList[1:]
        return commandTypeStr, args

    def waitForCommandResponse(self, s):
        header, msg = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        if msgType != b'\x01\x10':
            raise Exception("Wrong message type!")
            s.close()
            return
        command, args = self.__decryptCommandResponseMsg(header + msg)
        if self.latestHash != args[0]:
            s.close()
            print("connection closed due to wrong hash")
            exit(1)
        commandsToFail = ['pwd', 'lst', 'chd', 'mkd', 'del']
        commandsToReject = ['upl', 'dnl']
        if command in commandsToReject:
            if args[1] == 'reject':
                print("command " + command + " rejected: " + args[2] )
            elif args[1] == 'success':
                self.__printResult(command, *args)

        elif command in commandsToFail:
            if args[1] == 'failure':
                print("command " + command + " failed: " + args[2])
            elif args[1] == 'success':
                self.__printResult(command, *args)
        else:
            s.close()

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
        # todo dnl is ir ki vmit?