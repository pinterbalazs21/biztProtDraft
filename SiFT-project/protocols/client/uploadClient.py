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
        msg_type = header[2:4]
        if msg_type != b'\x02\x10':
            raise CloseConnectionException("Wrong message type: " + msg_type + "instead of 02 10")
        msg = self.MTP.decrypt_and_verify(header + tail).decode("utf-8")
        msg_payload = msg.split("\n")
        received_file_hash = msg_payload[0]
        print(received_file_hash)
        received_file_size = int(msg_payload[1])
        print(received_file_size)

        local_file_hash, local_file_size = get_file_info(filename)
        print(local_file_hash)
        print(local_file_size)

        if local_file_hash != received_file_hash:
            raise CloseConnectionException("File hash of uploaded file and local file are different! Closing connection.")
        if local_file_size != received_file_size:
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
            next_chunk = f.read(1024)

            while True:
                if not chunk:
                    break
                elif not next_chunk:
                    dnloadres = self.__create_and_encrypt_chunk(chunk, isLast=True)
                else:
                    dnloadres = self.__create_and_encrypt_chunk(chunk)
                print("Sending next file chunk...")
                self.__send_chunk(dnloadres, s)
                chunk = next_chunk
                next_chunk = f.read(1024)

    def execute_upload_protocol(self, path, s):
        try:
            # let's send the file
            self.__send_file_chunks(path, s)
            self.__wait_for_response(path, s)
        except CloseConnectionException as ce:
            raise ce
        except Exception as e:
            CloseConnectionException(str(e))
