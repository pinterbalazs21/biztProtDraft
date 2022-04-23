'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''
import os.path

class ClientDownloadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def __createAndEncryptDownloadRequest(self, cancel=False):
        if (cancel):
            dnlRequest = "Cancel".encode("utf-8")
        else:
            dnlRequest = "Ready".encode("utf-8")
        msg = self.MTP.encryptAndAuth(b'\x03\x00', dnlRequest)
        return msg

    def __cancelDownload(self, s):
        encryptedDownloadRequest = self.__createAndEncryptDownloadRequest(cancel=True)
        s.sendall(encryptedDownloadRequest)

    def __receiveNextFileChunk(self, s):
        header = s.recv(16)
        MTPdata_size = header[4:6]
        msgType = header[2:4]
        len = int.from_bytes(MTPdata_size, byteorder='big')
        if len == 0:
            exit(1)  # TODO proper error handling
        tail = s.recv(len - 16)
        if msgType != b'\x03\x10' and msgType != b'\x03\x11':
            # TODO proper error handling (close connection or what to do?)
            raise ValueError("Wrong message type (should be 0310 or 0311): " + msgType.hex())
        msg = self.MTP.decryptAndVerify(header + tail)
        return msgType, msg

    def __receiveAndSaveFile(self, filename, s):
        # open file first in write mode (overrides file if it exists!)
        with open(filename, 'wb') as f:
            print("Saving next file chunk...")
            typ, msg = self.__receiveNextFileChunk(s)
            f.write(msg)

        # append the rest
        with open(filename, 'ab') as f:
            while typ != b'\x03\x11':
                print("Saving next file chunk...")
                typ, msg = self.__receiveNextFileChunk(s)
                f.write(msg)
        print("File downloaded successfully")

    def executeDownloadProtocol(self, filename, s):
        # file has to be saved into the current working directory, so path is removed here
        filename = os.path.basename(filename)

        ans = "unknown"
        while ans.lower() != "n" and ans.lower() != "y" and ans != "":
            print("File is ready to be downloaded. Do you want to proceed? [Y/n]", end=" ")
            ans = input().strip("\n")

        if ans == "n":
            self.__cancelDownload(s)
            print("Download canceled.")
            return

        encryptedDownloadRequest = self.__createAndEncryptDownloadRequest()
        s.sendall(encryptedDownloadRequest)
        self.__receiveAndSaveFile(filename, s)
