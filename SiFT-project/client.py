import socket

from protocols.client.loginClient import ClientLoginProtocol
from protocols.commands import CommandsProtocol
from protocols.mtp import MTP

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
                #todo handle args
                reqMsg = self.commandHandler.encryptCommandReq(command)
                print("reqMsg constructed")
                s.sendall(reqMsg)
                self.receiveCommandResponse(s)

    def receiveCommandResponse(self, s):
        header = s.recv(16)
        MTPdata_size = header[4:6]
        msgType = header[2:4]
        len = int.from_bytes(MTPdata_size, byteorder='big')
        if (len == 0):
            exit(1)
        tail = s.recv(len - 16)
        if msgType == b'\x01\x10':
            command, args = self.commandHandler.decryptCommandMsg(header + tail)
            #todo args[0] hash, kell vele vmit csinalni?
            for a in args:
                print(a)
            commandsToFail = ['pwd', 'lst', 'chd', 'mkd', 'del']
            commandsToReject = ['upl', 'dnl']
            if command in commandsToReject:
                if args[1] == 'reject':
                    print("command " + command + " rejected: " + args[2] )
                    s.close()
                elif args[1] == 'succes':
                    self.printResult(command, args)

            elif command in commandsToFail and args[1] == "failure":
                print("command " + command + " failed: " + args[2])
                s.close()


    def printResult(self, command, args):
        if command == ("pwd" or "lst"):
            print(args[3])
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