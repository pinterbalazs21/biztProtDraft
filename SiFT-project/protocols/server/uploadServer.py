'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''
import os.path

from protocols.common.utils import getHash


class ServerUploadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def __receiveNextFileChunk(self, s):
        header, msg = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        payload = self.MTP.decryptAndVerify(header + msg)
        if msgType != b'\x02\x00' and msgType != b'\x02\x01':
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
            while typ != b'\x02\x01':
                print("Saving next file chunk...")
                typ, msg = self.__receiveNextFileChunk(s)
                f.write(msg)
        print("File downloaded successfully")

    def __createAndEncryptUploadResponse(self, filename, s):
        fileSize = os.path.getsize(filename)
        file = open(filename, "r").read().encode("utf-8")
        fileHash = getHash(file)
        resPayload = str(fileHash + '\n' + fileSize)

        msg = self.MTP.encryptAndAuth(b'\x02\x10', resPayload)
        return msg

    def executeUploadProtocol(self, filename, s):
        if os.path.exists(filename):
            print("File to be uploaded will override already existing file.")
        self.__receiveAndSaveFile(filename, s)
        resp = self.__createAndEncryptUploadResponse(filename, s)
        s.sendall(resp)

