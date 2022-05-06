import socket

from protocols.client.commandsClient import ClientCommandsProtocol
from protocols.client.loginClient import ClientLoginProtocol
from protocols.client.downloadClient import ClientDownloadProtocol
from protocols.client.uploadClient import ClientUploadProtocol
from protocols.common.closeConnectionException import CloseConnectionException
from protocols.mtp import MTP


class SiFTClient():
    def __init__(self, port=5150):
        self.port = port
        self.host = "localhost" # "10.71.0.43" #  "localhost" # TODO put IP of server here
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
            try:
                self.loginHandler.executeLogin(s)
            except CloseConnectionException as ce:
                print("Close Connection Exception caught:")
                print(ce)
                s.close()
                print("Connection closed, thread terminated")
                return

            # start commands protocol
            while True:
                try:
                    rawCommmand = input()
                    self.commandHandler.commandHandling(rawCommmand, s, self.downloadHandler, self.uploadHandler)
                except CloseConnectionException as ce:
                    print("Close Connection Exception caught:")
                    print(ce)
                    s.close()
                    print("Connection closed, thread terminated")
                    return

client = SiFTClient()
client.connect()
