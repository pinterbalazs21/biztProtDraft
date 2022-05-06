'''
The SiFT v1.0 Upload Protocol is responsible for executing an actual file upload operation. It must only be used by the
server after sending an 'accept' response to an upl command in the Commands Protocol, and it must only be used by the
client after receiving an 'accept' response to an upl command in the Commands Protocol.
'''
import os.path
import sys
import traceback

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import getHash, getFileInfo


class ClientUploadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def __waitForResponse(self, filename, s):
        print("Upload complete, waiting for server to respond...")
        header, tail = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        if msgType != b'\x02\x10':
            raise CloseConnectionException("Wrong message type: " + msgType + "instead of 02 10")
        msg = self.MTP.decryptAndVerify(header+tail).decode("utf-8")
        msgPayload = msg.split("\n")
        receivedFileHash = msgPayload[0]
        print(receivedFileHash)
        receivedFileSize = int(msgPayload[1])
        print(receivedFileSize)

        localFileHash, localFileSize = getFileInfo(filename)
        print(localFileHash)
        print(localFileSize)

        if localFileHash != receivedFileHash:
            raise CloseConnectionException("File hash of uploaded file and local file are different! Closing connection.")
        if localFileSize != receivedFileSize:
            raise CloseConnectionException("File size of uploaded file and local file are different! Closing connection.")

    def __createAndEncryptChunk(self, f, isLast=False):
        if isLast:
            dnloadres = self.MTP.encryptAndAuth(b'\x02\x01', f)
        else:
            dnloadres = self.MTP.encryptAndAuth(b'\x02\x00', f)
        return dnloadres

    def __sendChunk(self, dnloadres, s):
        s.sendall(dnloadres)

    def __sendFileChunks(self, filename, s):
        with open(filename, "rb") as f:
            chunk = f.read(1024)
            nextChunk = f.read(1024)

            while True:
                if not chunk:
                    break
                elif not nextChunk:
                    dnloadres = self.__createAndEncryptChunk(chunk, isLast=True)
                else:
                    dnloadres = self.__createAndEncryptChunk(chunk)
                print("Sending next file chunk...")
                self.__sendChunk(dnloadres, s)
                chunk = nextChunk
                nextChunk = f.read(1024)

    def executeUploadProtocol(self, path, s):
        try:
            # let's send the file
            self.__sendFileChunks(path, s)
            self.__waitForResponse(path, s)
        except CloseConnectionException as ce:
            raise ce
        except Exception as e:
            CloseConnectionException(str(e))