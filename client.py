class SiFTClient():

    def __init__(self, port = 5150):
        self.port = port
        self.key = "todoGetKey"
        print("init on port" + str(self.port))

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
