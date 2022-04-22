import socket

from protocols.client.loginClient import ClientLoginProtocol
from protocols.commands import CommandsProtocol
from protocols.mtp import MTP
import base64

class SiFTClient():

    def __init__(self, port = 5150):
        self.port = port
        self.host = "localhost"
        self.key = ""
        self.msgHandler = MTP()
        self.loginHandler = ClientLoginProtocol(self.msgHandler)
        self.commandHandler = CommandsProtocol(self.msgHandler)
        print("init on port" + str(self.port))

    def connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))

            # execute login protocol
            self.loginHandler.executeLogin(s)

            # start commands protocol
            while True:
                rawCommmand = input()
                command = rawCommmand.split()[0]
                commands = ['pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl']
                if command not in commands:
                    print("Please enter a valid command")
                    #todo arg validation here?
                    continue
                args = ()
                if len(command) > 1:
                    args = tuple(rawCommmand.split()[1:])
                reqMsg = self.commandHandler.encryptCommandReq(command, *args)
                print("reqMsg constructed")
                s.sendall(reqMsg)
                self.receiveCommandResponse(s, reqMsg)

    def receiveCommandResponse(self, s, reqMsg):
        header = s.recv(16)
        MTPdata_size = header[4:6]
        msgType = header[2:4]
        len = int.from_bytes(MTPdata_size, byteorder='big')
        if (len == 0):
            exit(1)
        tail = s.recv(len - 16)
        if msgType == b'\x01\x10':
            command, args = self.commandHandler.decryptCommandMsg(header + tail)
            originalHash = self.commandHandler.getHash(reqMsg)
            if originalHash != args[0]:
                s.close()
                print("connection closed due to wrong hash")
                exit(1)
            commandsToFail = ['pwd', 'lst', 'chd', 'mkd', 'del']
            commandsToReject = ['upl', 'dnl']
            if command in commandsToReject:
                if args[1] == 'reject':
                    print("command " + command + " rejected: " + args[2] )
                elif args[1] == 'success':
                    self.printResult(command, *args)

            elif command in commandsToFail:
                if args[1] == 'failure':
                    print("command " + command + " failed: " + args[2])
                elif args[1] == 'success':
                    print("success")
                    self.printResult(command, *args)
            else:
                s.close()


    def printResult(self, command, *args):
        if command == "pwd":
            print(args[2])
        elif command == "lst":
            if len(args) < 3: #empty dir handling
                print("")
                return
            encodedLst = args[2]
            decodedBytes = base64.b64decode(encodedLst.encode('utf-8'))
            print(decodedBytes.decode("utf-8"))
        else:
            print(command)
        #todo dnl is ir ki vmit?

    def pwd(self):
        #Print current working directory
        print("pwd")


    def lst(self):
        #List content of the current working directory
        print("lst")

    def mkd(self, dirName):
        """
        Make directory: Creates a new directory on the server. 
        The name of the directory to be created is provided as 
        an argument to the mkd command.
        """
        print("mkd " + dirName)
    def delete(self):
        """
        Delete file or directory: Deletes a file or a directory 
        on the server. The name of the file or directory to be 
        deleted is provided as an argument to the del command.
        """
        print("del")

    def upl(self):
        """
        Upload file: Uploads a file from the client to the server. 
        The name of the file to be uploaded is provided as an 
        argument to the upl command and the file is put in the 
        current working directory on the server.
        """
        print("upl")

    def dnl(self, fileName):
        """
        Download file: 
        Downloads a file from the current working directory of the 
        server to the client. The name of the file to be downloaded 
        is provided as an argument to the dnl command.
        """
        print("dnl " + fileName)


client = SiFTClient()
client.connect()