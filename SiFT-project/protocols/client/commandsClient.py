import base64
import os
from Crypto.Hash import SHA256

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import get_file_info


class ClientCommandsProtocol:
    def __init__(self, mtp):
        self.MTP = mtp

    # creates command request body
    # type can be: 'pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl'
    def __create_command_req(self, req_type, *args):
        request = req_type
        if args:  # has at least 1 param
            for parameter in args:
                request = request + "\n" + str(parameter)
        return request.encode("utf-8")

    def __encrypt_command_req(self, command_type, *args):
        payload = self.__create_command_req(command_type, *args)
        return self.MTP.encrypt_and_auth(b'\x01\x00', payload), payload

    def __save_hash(self, msg):
        print("payload: ", msg)
        print("payload hex: ", msg.hex())
        h = SHA256.new()
        h.update(msg)
        self.latestHash = h.hexdigest()

    def send_PWD_req(self, s):
        msg, payload = self.__encrypt_command_req("pwd")
        s.sendall(msg)
        self.__save_hash(payload)

    def send_LST_req(self, s):
        msg, payload = self.__encrypt_command_req("lst")
        s.sendall(msg)
        self.__save_hash(payload)

    def send_CHD_req(self, s, directory):
        msg, payload = self.__encrypt_command_req("chd", directory)
        s.sendall(msg)
        self.__save_hash(payload)

    def send_MKD_req(self, s, folder_name):
        msg, payload = self.__encrypt_command_req("mkd", folder_name)
        s.sendall(msg)
        self.__save_hash(payload)

    def send_DEL_req(self, s, file_name):
        msg, payload = self.__encrypt_command_req("del", file_name)
        s.sendall(msg)
        self.__save_hash(payload)

    def send_UPL_req(self, s, file_name):
        fileHash, fileSize = get_file_info(file_name)
        msg, payload = self.__encrypt_command_req("upl", os.path.basename(file_name), fileSize, fileHash)
        s.sendall(msg)
        self.__save_hash(payload)

    def send_DNL_req(self, s, file_name):
        msg, payload = self.__encrypt_command_req("dnl", file_name)
        s.sendall(msg)
        self.__save_hash(payload)

    def __decrypt_command_response_msg(self, raw_msg):
        decrypted_payload = self.MTP.decrypt_and_verify(raw_msg).decode("utf-8")
        command_list = decrypted_payload.split("\n")
        command_type_str = command_list[0]
        args = ()
        if len(command_list) > 1:
            args = command_list[1:]
        return command_type_str, args

    def wait_for_command_response(self, s):
        header, msg = self.MTP.wait_for_message(s)
        msg_type = header[2:4]
        if msg_type != b'\x01\x10':
            raise CloseConnectionException("Wrong message type: " + msg_type + " instead of 01 10")
        command, args = self.__decrypt_command_response_msg(header + msg)
        print("hash: ", args[0])
        print("latest hash: ", self.latestHash)
        if self.latestHash != args[0]:
            raise CloseConnectionException("Wrong hash in command response")
        commands_to_fail = ['pwd', 'lst', 'chd', 'mkd', 'del']
        commands_to_reject = ['upl', 'dnl']
        if command in commands_to_reject:
            if args[1] == 'reject':
                print("command " + command + " rejected: " + args[2])
                return False
            elif args[1] == 'accept':
                self.__print_result(command, *args)
                return True
        elif command in commands_to_fail:
            if args[1] == 'failure':
                print("command " + command + " failed: " + args[2])
                return False
            elif args[1] == 'success':
                self.__print_result(command, *args)
                return True
        else:
            raise CloseConnectionException("Command in command response unknown: " + command)

    def __print_result(self, command, *args):
        if command == "pwd":
            print(args[2])
        elif command == "lst":
            if len(args) < 3:  # empty dir handling
                print("")
                return
            encoded_lst = args[2]
            decoded_bytes = base64.b64decode(encoded_lst.encode('utf-8'))
            print(decoded_bytes.decode("utf-8"))
        elif command == "dnl":
            self.latestFilesize = args[2]
            self.latestFilehash = args[3]
            print("Hash of the file to be downloaded is: ", self.latestFilesize)
            print("Size of the file to be downloaded is: ", self.latestFilehash)

    def handle_command(self, raw_command, s, download_handler, upload_handler):
        command = raw_command.split()[0]
        if command == 'pwd' and len(raw_command.split()) == 1:
            self.send_PWD_req(s)
            self.wait_for_command_response(s)
        elif command == 'lst' and len(raw_command.split()) == 1:
            self.send_LST_req(s)
            self.wait_for_command_response(s)
        elif command == 'chd' and len(raw_command.split()) == 2:
            self.send_CHD_req(s, raw_command.split()[1])
            self.wait_for_command_response(s)
        elif command == 'mkd' and len(raw_command.split()) == 2:
            self.send_MKD_req(s, raw_command.split()[1])
            self.wait_for_command_response(s)
        elif command == 'del' and len(raw_command.split()) == 2:
            self.send_DEL_req(s, raw_command.split()[1])
            self.wait_for_command_response(s)
        elif command == 'upl' and len(raw_command.split()) == 2:
            file_name = raw_command.split()[1]
            if not os.path.isfile(file_name):
                print("file not found")
                return
            self.send_UPL_req(s, raw_command.split()[1])
            if self.wait_for_command_response(s):
                upload_handler.execute_upload_protocol(file_name, s)
        elif command == 'dnl' and len(raw_command.split()) == 2:
            file_name = raw_command.split()[1]
            self.send_DNL_req(s, file_name)
            if self.wait_for_command_response(s):
                download_handler.execute_download_protocol(file_name, self.latestFilehash, s)
        else:
            print("Please enter a valid command")