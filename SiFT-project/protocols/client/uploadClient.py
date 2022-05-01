'''
The SiFT v1.0 Upload Protocol is responsible for executing an actual file upload operation. It must only be used by the
server after sending an 'accept' response to an upl command in the Commands Protocol, and it must only be used by the
client after receiving an 'accept' response to an upl command in the Commands Protocol.
'''
import sys
import traceback

class ClientUploadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def __createAndEncryptChunk(self, f, isLast=False):
        if isLast:
            dnloadres = self.MTP.encryptAndAuth(b'\x03\x11', f)
        else:
            dnloadres = self.MTP.encryptAndAuth(b'\x03\x10', f)
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
        try: # TODO this should be removed and proper error handling added - we have to close connection in a lot of cases, see specification
            # let's send the file
            self.__sendFileChunks(path, s)
        except Exception as e:
            traceback.print_exception(*sys.exc_info())
            print(e)