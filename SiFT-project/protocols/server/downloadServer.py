'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''


class ServerDownloadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    # TODO MTP part of message should be handled by mtp
    def __waitForDownloadRequest(self, s):
        header, tail = self.MTP.waitForMessage(s)
        msgType = header[2:4]
        if msgType != b'\x03\x00':
            # TODO proper error handling (close connection or what to do?)
            raise ValueError("Wrong message type (should be 03 00): " + msgType)
        msg = self.MTP.decryptAndVerify(header+tail)
        if msg == b'Cancel':
            return False
        elif msg == b'Ready':
            return True
        else:
            # TODO proper error handling (close connection or what to do?)
            raise ValueError("Bad download request (not Cancel or Ready): " + str(msg))

    def __read_in_chunks(self, file_object, chunk_size=1024):
        """
        Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        Source: https://stackoverflow.com/questions/519633/lazy-method-for-reading-big-file-in-python
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def __createAndEncryptChunk(self, f, isLast=False):
        binF = f.encode("utf-8")
        if isLast:
            dnloadres = self.MTP.encryptAndAuth(b'\x03\x11', binF)
        else: dnloadres = self.MTP.encryptAndAuth(b'\x03\x10', binF)
        return dnloadres

    def __sendChunk(self, dnloadres, s):
        s.sendall(dnloadres)

    def __sendFileChunks(self, filename, s):
        with open(filename) as f:
            while True:
                try:
                    chunk = next(self.__read_in_chunks(f)) # TODO ez az utolsot duplikálja, majd kiszedni
                    dnloadres = self.__createAndEncryptChunk(chunk)
                    self.__sendChunk(dnloadres, s)
                except StopIteration as e:
                    dnloadres = self.__createAndEncryptChunk(chunk, isLast=True)
                    self.__sendChunk(dnloadres, s)
                    break

    def executeDownloadProtocol(self, filename, s):
        # wait for download request
        if not self.__waitForDownloadRequest(s):  # Cancel
            return # TODO anything else to clean up here?

        # received Ready from client, let's send the file
        fileChunks = self.__sendFileChunks(filename, s)