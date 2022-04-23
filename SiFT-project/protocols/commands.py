from Crypto.Hash import SHA256

# TODO break it into server and client part
class CommandsProtocol:
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

    #creates command response body
    def __createCommandRes(self, type, requestPayload, *args):
        response = type + "\n" + self.getHash(requestPayload)
        if args:# has at least 1 param
            for resp in args:
                response = response + "\n" + resp
        return response.encode("utf-8")

    def encryptCommandReq(self, commandType, *args):
        payload = self.__createCommandReq(commandType, *args)
        return self.MTP.encryptAndAuth(b'\x01\x00', payload)

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

    def getHash(self, payload):
        h = SHA256.new()
        h.update(payload)
        return h.hexdigest()