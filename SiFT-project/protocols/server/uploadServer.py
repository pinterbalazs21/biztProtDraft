'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''
import os.path

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import get_hash, get_file_info


class ServerUploadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def __receive_next_file_chunk(self, s):
        header, msg = self.MTP.wait_for_message(s)
        msgType = header[2:4]
        payload = self.MTP.decrypt_and_verify(header + msg)
        if msgType != b'\x02\x00' and msgType != b'\x02\x01':
            raise CloseConnectionException("Wrong message type: " + msgType + "instead of 02 00 or 02 10")
        return msgType, payload

    def __receive_and_save_file(self, filename, s):
        # open file first in write mode (overrides file if it exists!)
        with open(filename, 'wb') as f:
            print("Saving next file chunk...")
            typ, msg = self.__receive_next_file_chunk(s)
            f.write(msg)

        # append the rest
        with open(filename, 'ab') as f:
            while typ != b'\x02\x01':
                print("Saving next file chunk...")
                typ, msg = self.__receive_next_file_chunk(s)
                f.write(msg)
        print("File uploaded successfully")

    def __create_and_encrypt_upload_response(self, filename, s):
        fileHash, fileSize = get_file_info(filename)
        resPayload = str(fileHash + "\n" + str(fileSize)).encode("utf-8")

        msg = self.MTP.encrypt_and_auth(b'\x02\x10', resPayload)
        return msg

    def execute_upload_protocol(self, filename, s):
        try:
            if os.path.exists(filename): # note: we can't reach this, as the upl command does not enable uploading files that already exist on the server
                print("File to be uploaded will override already existing file.")
            self.__receive_and_save_file(filename, s)
            resp = self.__create_and_encrypt_upload_response(filename, s)
            s.sendall(resp)
        except CloseConnectionException as ce:
            raise ce
        except Exception as e:
            CloseConnectionException(str(e))
