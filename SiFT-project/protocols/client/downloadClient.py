'''
The SiFT v1.0 Download Protocol is responsible for executing an actual file download operation.
It must only be used by the server after sending an 'accept' response to a dnl command in the Commands Protocol,
and it must only be used by the client after receiving an 'accept' response to a dnl command in the Commands Protocol.
'''
import os.path

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import get_hash


class ClientDownloadProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    def __create_and_encrypt_download_request(self, cancel=False):
        if cancel:
            dnl_request = "Cancel".encode("utf-8")
        else:
            dnl_request = "Ready".encode("utf-8")
        msg = self.MTP.encrypt_and_auth(b'\x03\x00', dnl_request)
        return msg

    def __cancel_download(self, s):
        encrypted_download_request = self.__create_and_encrypt_download_request(cancel=True)
        s.sendall(encrypted_download_request)

    def __receive_next_file_chunk(self, s):
        header, msg = self.MTP.wait_for_message(s)
        msg_type = header[2:4]
        payload = self.MTP.decrypt_and_verify(header + msg)
        if msg_type != b'\x03\x10' and msg_type != b'\x03\x11':
            raise CloseConnectionException("Wrong message type: " + msg_type + "instead of 03 00 or 03 10")
        return msg_type, payload

    def __receive_and_save_file(self, filename, received_file_hash, s):
        # open file first in write mode (overrides file if it exists!)
        with open(filename, 'wb') as f:
            print("Saving next file chunk...")
            typ, msg = self.__receive_next_file_chunk(s)
            f.write(msg)

        # append the rest
        with open(filename, 'ab') as f:
            while typ != b'\x03\x11':
                print("Saving next file chunk...")
                typ, msg = self.__receive_next_file_chunk(s)
                f.write(msg)

        file = open(filename, "r")
        text_file = file.read().encode("utf-8")
        downloaded_file_hash = get_hash(text_file)
        if downloaded_file_hash != received_file_hash:
            raise CloseConnectionException("Hash faulty, closing connection!")
        print("File downloaded successfully")
        file.close()

    def execute_download_protocol(self, filename, filehash, s):
        try:
            # file has to be saved into the current working directory, so path is removed here
            filename = os.path.basename(filename)

            ans = "unknown"
            while ans.lower() != "n" and ans.lower() != "y" and ans != "":
                print("File is ready to be downloaded. Do you want to proceed? [Y/n]", end=" ")
                ans = input().strip("\n")

            if ans == "n":
                self.__cancel_download(s)
                print("Download canceled.")
                return

            encrypted_download_request = self.__create_and_encrypt_download_request()
            s.sendall(encrypted_download_request)
            self.__receive_and_save_file(filename, filehash, s)
        except CloseConnectionException as ce:
            raise ce
        except Exception as e:
            CloseConnectionException(str(e))
