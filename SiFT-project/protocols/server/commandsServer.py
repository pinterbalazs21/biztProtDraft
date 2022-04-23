from Crypto.Hash import SHA256

class ServerCommandsProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def getHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        return h.hexdigest()

    # creates command response body
    def __createCommandRes(self, type, requestPayload, *args):
        response = type + "\n" + self.getHash(requestPayload)
        if args:# has at least 1 param
            for resp in args:
                response = response + "\n" + resp
        return response.encode("utf-8")

    def encryptCommandRes(self, commandType, requestPayload, *args):
        payload = self.__createCommandRes(commandType, requestPayload, *args)
        return self.MTP.encryptAndAuth(b'\x01\x10', payload)

    def decryptCommandMsg(self, rawMSG):
        #todo type verification and exception? (b'\x01\x10' or b'\x01\x00')
        decryptedPayload = self.MTP.decryptAndVerify(rawMSG).decode("utf-8")
        commandList = decryptedPayload.splitlines()
        commandTypeStr = commandList[0]
        args = ()
        if len(commandList) > 1:
            args = commandList[1:]
        return commandTypeStr, args