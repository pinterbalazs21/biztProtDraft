'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''
import sys
import traceback

from protocols.common.closeConnectionException import CloseConnectionException


class ServerDownloadProtocol:
    def __init__(self, mtp):
        self.MTP = mtp

    def __wait_for_download_request(self, s):
        header, tail = self.MTP.wait_for_message(s)
        msg_type = header[2:4]
        if msg_type != b'\x03\x00':
            raise CloseConnectionException("Wrong message type: " + msg_type + "instead of 03 00")
        msg = self.MTP.decrypt_and_verify(header + tail)
        if msg == b'Cancel':
            print("Received \'Cancel\' download request of download protocol from client")
            return False
        elif msg == b'Ready':
            print("Received \'Ready\' download request of download protocol from client")
            return True
        else:
            raise CloseConnectionException("Bad download request (not Cancel or Ready)")

    def __create_and_encrypt_chunk(self, f, is_last=False):
        if is_last:
            dnloadres = self.MTP.encrypt_and_auth(b'\x03\x11', f)
        else: 
            dnloadres = self.MTP.encrypt_and_auth(b'\x03\x10', f)
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
                    dnloadres = self.__create_and_encrypt_chunk(chunk, is_last=True)
                else:
                    dnloadres = self.__create_and_encrypt_chunk(chunk)
                print("Sending next file chunk...")
                self.__send_chunk(dnloadres, s)
                chunk = next_chunk
                next_chunk = f.read(1024)

    def execute_download_protocol(self, path, s):
        try:
            # wait for download request
            if not self.__wait_for_download_request(s):  # Cancel
                return
            # received Ready from client, let's send the file
            self.__send_file_chunks(path, s)
        except CloseConnectionException as ce:
            raise ce
        except Exception as e:
            raise CloseConnectionException(str(e))