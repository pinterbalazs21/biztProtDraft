'''
The SiFT v1.0 Upload Protocol is responsible for executing an actual file upload operation. It must only be used by the
server after sending an 'accept' response to an upl command in the Commands Protocol, and it must only be used by the
client after receiving an 'accept' response to an upl command in the Commands Protocol.
'''
import os.path
import sys
import traceback

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import get_hash, get_file_info


class ClientUploadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def __wait_for_response(self, filename, s):
        print("Upload complete, waiting for server to respond...")
        header, tail = self.MTP.wait_for_message(s)
        msgType = header[2:4]
        if msgType != b'\x02\x10':
            raise CloseConnectionException("Wrong message type: " + msgType + "instead of 02 10")
        msg = self.MTP.decrypt_and_verify(header + tail).decode("utf-8")
        msgPayload = msg.split("\n")
        receivedFileHash = msgPayload[0]
        print(receivedFileHash)
        receivedFileSize = int(msgPayload[1])
        print(receivedFileSize)

        localFileHash, localFileSize = get_file_info(filename)
        print(localFileHash)
        print(localFileSize)

        if localFileHash != receivedFileHash:
            raise CloseConnectionException("File hash of uploaded file and local file are different! Closing connection.")
        if localFileSize != receivedFileSize:
            raise CloseConnectionException("File size of uploaded file and local file are different! Closing connection.")

    def __create_and_encrypt_chunk(self, f, isLast=False):
        if isLast:
            dnloadres = self.MTP.encrypt_and_auth(b'\x02\x01', f)
        else:
            dnloadres = self.MTP.encrypt_and_auth(b'\x02\x00', f)
        return dnloadres

    def __send_chunk(self, dnloadres, s):
        s.sendall(dnloadres)

    def __send_file_chunks(self, filename, s):
        with open(filename, "rb") as f:
            chunk = f.read(1024)
            nextChunk = f.read(1024)

            while True:
                if not chunk:
                    break
                elif not nextChunk:
                    dnloadres = self.__create_and_encrypt_chunk(chunk, isLast=True)
                else:
                    dnloadres = self.__create_and_encrypt_chunk(chunk)
                print("Sending next file chunk...")
                self.__send_chunk(dnloadres, s)
                chunk = nextChunk
                nextChunk = f.read(1024)

    def execute_upload_protocol(self, path, s):
        try:
            # let's send the file
            self.__send_file_chunks(path, s)
            self.__wait_for_response(path, s)
        except CloseConnectionException as ce:
            raise ce
        except Exception as e:
            CloseConnectionException(str(e))