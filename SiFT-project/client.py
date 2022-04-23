import socket

from protocols.client.commandsClient import ClientCommandsProtocol
from protocols.client.downloadClient import ClientDownloadProtocol
from protocols.client.loginClient import ClientLoginProtocol
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
                commands = ['pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl']
                if command not in commands:
                    print("Please enter a valid command")
                    # todo arg validation here?
                    continue
                args = ()
                if len(command) > 1:
                    args = tuple(rawCommmand.split()[1:])
                if command == "dnl": # TODO refactor, put in command protocol, break into per command process
                    filename = args[0]
                    reqMsg = self.commandHandler.encryptCommandReq(command, *args)
                    print("reqMsg constructed")
                    s.sendall(reqMsg)
                    self.__receiveDownloadCommandResponse(s, reqMsg, filename)
                else:
                    reqMsg = self.commandHandler.encryptCommandReq(command, *args)
                    print("reqMsg constructed")
                    s.sendall(reqMsg)
                    self.__receiveCommandResponse(s, reqMsg)

    # TODO shouldn't this be in the client command protocol?
    def __receiveCommandResponse(self, s, reqMsg):
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
            # commandsToReject = ['upl', 'dnl']
            # if command in commandsToReject:
            #     if args[1] == 'reject':
            #         print("command " + command + " rejected: " + args[2])
            #     elif args[1] == 'success':
            #         if command == 'dnl':
            #             self.downloadHandler.executeDownloadProtocol(, s) # TODO that's why the whole process of these command req-resps should be in the commandsprotcol, implemented per command - how do I get the filename HERE??
            #         # elif command == 'upl': # TODO
            #         else:
            #             self.__printResult(command, *args)

            if command in commandsToFail:
                if args[1] == 'failure':
                    print("command " + command + " failed: " + args[2])
                elif args[1] == 'success':
                    print("success")
                    self.__printResult(command, *args)
            else:
                s.close()

    def __printResult(self, command, *args):
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
        # TODO dnl is ir ki vmit? - nem, szerintem nem, csak lementi a fájlt

    # TODO shouldn't this be in the client command protocol?
    def __receiveDownloadCommandResponse(self, s, reqMsg, filename):
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
            commandsToReject = ['upl', 'dnl']
            if command in commandsToReject:
                if args[1] == 'reject':
                    print("command " + command + " rejected: " + args[2])
                elif args[1] == 'success':
                    if command == 'dnl':
                        self.downloadHandler.executeDownloadProtocol(filename, s)
                    # elif command == 'upl': # TODO
            else:
                s.close()

# TODO will these methods below be used anywhere? If not, remove them please

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