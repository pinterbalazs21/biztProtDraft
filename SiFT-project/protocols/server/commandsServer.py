from Crypto.Hash import SHA256

class ServerCommandsProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def getHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        return h.hexdigest()

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
        self.latestHash = self.getHash(rawMSG)
        command, args = self.decryptCommandMsg(rawMSG)
        return command, args

    #def handleCommandReq(self, s, downloadHandler):
