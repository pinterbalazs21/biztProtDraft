'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''


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
        header, msg = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        payload = self.MTP.decryptAndVerify(header + msg)
        if msgType != b'\x03\x10' and msgType != b'\x03\x11':
            # TODO proper error handling (close connection or what to do?)
            raise ValueError("Wrong message type (should be 03 10 or 03 10): ")
        return msgType, payload

    # TODO where to save file?
    def __receiveAndSaveFile(self, filename, s):
        # open file first in write mode (overrides file if it exists!)
        with open(filename, 'wb') as f:
            typ, msg = self.__receiveNextFileChunk(s)
            f.write(msg)

        # append the rest
        with open(filename, 'ab') as f:
            while typ != b'\x03\x11':
                typ, msg = self.__receiveNextFileChunk(s)
                f.write(msg)

    def executeDownloadProtocol(self, filename, s):
        ans = "y"
        #while ans.lower() != "n" or ans.lower() != "y" or ans != "":
        #    print(ans)
        #    print("File is ready to be downloaded. Do you want to proceed? [Y/n]", end=" ")
        #    ans = input()
#
        #if ans == "n":
        #    self.__cancelDownload(s)
        #    print("Download canceled.")
        #    return

        encryptedDownloadRequest = self.__createAndEncryptDownloadRequest()
        s.sendall(encryptedDownloadRequest)
        self.__receiveAndSaveFile(filename, s)
