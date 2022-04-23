from Crypto.Hash import SHA256


class ClientCommandsProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    # creates command request body
    # type can be: 'pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl'
    def __createCommandReq(self, type, *args):
        #todo type check or different function for each command
        request = type
        if args:  # has at least 1 param
            for parameter in args:
                request = request + "\n" + parameter
        return request.encode("utf-8")

    def encryptCommandReq(self, commandType, *args):
        payload = self.__createCommandReq(commandType, *args)
        return self.MTP.encryptAndAuth(b'\x01\x00', payload)

    def decryptCommandMsg(self, rawMSG):
        #todo type verification and exception? (b'\x01\x10' or b'\x01\x00')
        decryptedPayload = self.MTP.decryptAndVerify(rawMSG).decode("utf-8")
        commandList = decryptedPayload.splitlines()
        commandTypeStr = commandList[0]
        args = ()
        if len(commandList) > 1:
            args = commandList[1:]
        return commandTypeStr, args

    def getHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        return h.hexdigest()