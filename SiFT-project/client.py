import socket
from MTP import MTP, LoginProtocol

class SiFTClient():

    def __init__(self, port = 5150):
        self.port = port
        self.host = "localhost"
        self.key = ""
        self.msgHandler = MTP()
        self.loginHandler = LoginProtocol(self.msgHandler)
        print("init on port" + str(self.port))

    def connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            name = 'BATMAN'
            pw = 'Z4QQQ'
            client_random, tk = self.sendConnReq(s, name, pw)
            self.recieveConnConf(s, client_random, tk)
            #todo command msg sending + file operation upload download stuff


    def sendConnReq(self, s, name, pw):
        loginPayload, client_random = self.loginHandler.createLoginReq(name, pw)
        loginPayload = str.encode(loginPayload)
        client_random = client_random.encode("utf-8")
        msg, tk = self.loginHandler.encryptLoginReq(loginPayload)
        s.sendall(msg)
        return client_random, tk

    def recieveConnConf(self, s, client_random, tk):
        header = s.recv(16)
        MTPdata_size = header[4:6]
        msgType = header[2:4]
        len = int.from_bytes(MTPdata_size, byteorder='big')
        if (len == 0):
            exit(1)
        tail = s.recv(len - 16)
        if msgType == b'\x00\x10':
            payload = self.loginHandler.decryptLoginRes(tk, header + tail)
            server_random = payload[65:]
            # final symmetric key:
            ikey = client_random + server_random
            salt = payload[:64]
            self.loginHandler.createFinalKey(ikey, salt)
            print("Connection established")
            return
        print("something went wrong (wrong message type)")

    def pwd(self):
        #Print current working directory
        print("pwd")

    def lst(self):
        #List content of the current working directory
        print("pwd")

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