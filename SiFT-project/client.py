import socket

from protocols.client.commandsClient import ClientCommandsProtocol
from protocols.client.downloadClient import ClientDownloadProtocol
from protocols.client.loginClient import ClientLoginProtocol
from protocols.client.downloadClient import ClientDownloadProtocol
from protocols.client.uploadClient import ClientUploadProtocol
from protocols.mtp import MTP
import base64

class SiFTClient():

    def __init__(self, port = 5150):
        self.port = port
        self.host = "localhost"
        self.key = ""
        self.msgHandler = MTP()
        self.loginHandler = ClientLoginProtocol(self.msgHandler)
        self.commandHandler = ClientCommandsProtocol(self.msgHandler)
        self.downloadHandler = ClientDownloadProtocol(self.msgHandler)
        self.uploadHandler = ClientUploadProtocol(self.msgHandler)
        print("init on port" + str(self.port))

    def connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))

            # execute login protocol
            self.loginHandler.executeLogin(s)

            # start commands protocol TODO shouldn't this loop be in the commands protocol?
            while True:
                rawCommmand = input()
                command = rawCommmand.split()[0]
                #commands = ['pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl']
                if command == 'pwd' and len(rawCommmand.split()) == 1:
                    self.commandHandler.sendPWDReq(s)
                    self.commandHandler.waitForCommandResponse(s)
                elif command == 'lst' and len(rawCommmand.split()) == 1:
                    self.commandHandler.sendLSTReq(s)
                    self.commandHandler.waitForCommandResponse(s)
                elif command == 'chd' and len(rawCommmand.split()) == 2:
                    self.commandHandler.sendCHDReq(s, rawCommmand.split()[1])
                    self.commandHandler.waitForCommandResponse(s)
                elif command == 'mkd' and len(rawCommmand.split()) == 2:
                    self.commandHandler.sendMKDReq(s, rawCommmand.split()[1])
                    self.commandHandler.waitForCommandResponse(s)
                elif command == 'del' and len(rawCommmand.split()) == 2:
                    self.commandHandler.sendDELReq(s, rawCommmand.split()[1])
                    self.commandHandler.waitForCommandResponse(s)
                elif command == 'upl' and len(rawCommmand.split()) == 2:
                    self.commandHandler.sendUPLReq(s, rawCommmand.split()[1])
                    if self.commandHandler.waitForCommandResponse(s):
                        self.uploadHandler.executeUploadProtocol(fileName, s)
                elif command == 'dnl' and len(rawCommmand.split()) == 2:
                    fileName = rawCommmand.split()[1]
                    self.commandHandler.sendDNLReq(s, fileName)
                    if self.commandHandler.waitForCommandResponse(s):
                        self.downloadHandler.executeDownloadProtocol(fileName, s)
                else:
                    print("Please enter a valid command")
                    continue

client = SiFTClient()
client.connect()