'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''
import sys
import traceback


class ServerDownloadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    # TODO MTP part of message should be handled by mtp
    def __waitForDownloadRequest(self, s):
        header = s.recv(16)
        MTPdata_size = header[4:6]
        msgType = header[2:4]
        len = int.from_bytes(MTPdata_size, byteorder='big')
        print("len: " + str(len))
        if (len == 0):
            exit(1) # TODO proper error handling
        # if (len < 16):
            # TODO what to do here (error handling needed, just as below)
        tail = s.recv(len - 16)
        if msgType != b'\x03\x00':
            # TODO proper error handling (close connection or what to do?)
            raise ValueError("Wrong message type (should be 03 00): " + msgType)

        msg = self.MTP.decryptAndVerify(header+tail)

        if msg == "Cancel".encode("utf-8"):
            print("Received \'Cancel\' download request of download protocol from client")
            return False
        elif msg == "Ready".encode("utf-8"):
            print("Received \'Ready\' download request of download protocol from client")
            return True
        else:
            # TODO proper error handling (close connection or what to do?)
            print(msg)
            raise ValueError("Bad download request (not Cancel or Ready)")

    def __createAndEncryptChunk(self, f, isLast=False):
        if isLast:
            dnloadres = self.MTP.encryptAndAuth(b'\x03\x11', f)
        else: dnloadres = self.MTP.encryptAndAuth(b'\x03\x10', f)
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
                elif not nextChunk:  # TODO check if this works
                    dnloadres = self.__createAndEncryptChunk(chunk, isLast=True)
                else:
                    dnloadres = self.__createAndEncryptChunk(chunk)
                print("Sending next file chunk...")
                self.__sendChunk(dnloadres, s)
                chunk = nextChunk
                nextChunk = f.read(1024)

    def executeDownloadProtocol(self, path, s):
        try: # TODO this should be removed and proper error handling added
            # wait for download request
            if not self.__waitForDownloadRequest(s):  # Cancel
                return # TODO anything else to clean up here?

            # received Ready from client, let's send the file
            self.__sendFileChunks(path, s)
        except Exception as e:
            traceback.print_exception(*sys.exc_info())
            print(e)