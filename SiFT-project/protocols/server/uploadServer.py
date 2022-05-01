'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''
import os.path

class ServerUploadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def __cancelDownload(self, s):
        encryptedDownloadRequest = self.__createAndEncryptDownloadRequest(cancel=True)
        s.sendall(encryptedDownloadRequest)

    def __receiveNextFileChunk(self, s):
        header, msg = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        payload = self.MTP.decryptAndVerify(header + msg)
        if msgType != b'\x03\x10' and msgType != b'\x03\x11':
            # TODO proper error handling (close connection or what to do?)
            raise ValueError("Wrong message type (should be 03 10 or 03 10): ")
        return msgType, payload

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

    def executeUploadProtocol(self, filename, s):
        if os.path.exists(filename):
            print("File to be uploaded will override already existing file.")
        self.__receiveAndSaveFile(filename, s)
