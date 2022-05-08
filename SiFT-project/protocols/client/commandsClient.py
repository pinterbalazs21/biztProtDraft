import base64
import os
from Crypto.Hash import SHA256

from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import get_file_info


class ClientCommandsProtocol:
    def __init__(self, MTP):
        self.MTP = MTP

    # creates command request body
    # type can be: 'pwd', 'lst', 'chd', 'mkd', 'del', 'upl', 'dnl'
    def __create_command_req(self, type, *args):
        request = type
        if args:  # has at least 1 param
            for parameter in args:
                request = request + "\n" + str(parameter)
        return request.encode("utf-8")

    def __encrypt_command_req(self, commandType, *args):
        payload = self.__create_command_req(commandType, *args)
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

    def send_CHD_req(self, s, dir):
        msg, payload = self.__encrypt_command_req("chd", dir)
        s.sendall(msg)
        self.__save_hash(payload)

    def send_MKD_req(self, s, folderName):
        msg, payload = self.__encrypt_command_req("mkd", folderName)
        s.sendall(msg)
        self.__save_hash(payload)

    def send_DEL_req(self, s, fName):
        msg, payload = self.__encrypt_command_req("del", fName)
        s.sendall(msg)
        self.__save_hash(payload)

    def send_UPL_req(self, s, fName):
        fileHash, fileSize = get_file_info(fName)
        msg, payload = self.__encrypt_command_req("upl", os.path.basename(fName), fileSize, fileHash)
        s.sendall(msg)
        self.__save_hash(payload)

    def send_DNL_req(self, s, fName):
        msg, payload = self.__encrypt_command_req("dnl", fName)
        s.sendall(msg)
        self.__save_hash(payload)

    def __decrypt_command_response_msg(self, rawMSG):
        decryptedPayload = self.MTP.decrypt_and_verify(rawMSG).decode("utf-8")
        commandList = decryptedPayload.split("\n")
        commandTypeStr = commandList[0]
        args = ()
        if len(commandList) > 1:
            args = commandList[1:]
        return commandTypeStr, args

    def wait_for_command_response(self, s):
        header, msg = self.MTP.wait_for_message(s)
        msgType = header[2:4]
        if msgType != b'\x01\x10':
            raise CloseConnectionException("Wrong message type: " + msgType + " instead of 01 10")
        command, args = self.__decrypt_command_response_msg(header + msg)
        print("hash: ", args[0])
        print("latest hash: ", self.latestHash)
        if self.latestHash != args[0]:
            raise CloseConnectionException("Wrong hash in command response")
        commandsToFail = ['pwd', 'lst', 'chd', 'mkd', 'del']
        commandsToReject = ['upl', 'dnl']
        if command in commandsToReject:
            if args[1] == 'reject':
                print("command " + command + " rejected: " + args[2])
                return False
            elif args[1] == 'accept':
                self.__print_result(command, *args)
                return True
        elif command in commandsToFail:
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
            encodedLst = args[2]
            decodedBytes = base64.b64decode(encodedLst.encode('utf-8'))
            print(decodedBytes.decode("utf-8"))
        elif command == "dnl":
            self.latestFilesize = args[2]
            self.latestFilehash = args[3]
            print("Hash of the file to be downloaded is: ", self.latestFilesize)
            print("Size of the file to be downloaded is: ", self.latestFilehash)

    def handle_command(self, rawCommmand, s, downloadHandler, uploadHandler):
        command = rawCommmand.split()[0]
        if command == 'pwd' and len(rawCommmand.split()) == 1:
            self.send_PWD_req(s)
            self.wait_for_command_response(s)
        elif command == 'lst' and len(rawCommmand.split()) == 1:
            self.send_LST_req(s)
            self.wait_for_command_response(s)
        elif command == 'chd' and len(rawCommmand.split()) == 2:
            self.send_CHD_req(s, rawCommmand.split()[1])
            self.wait_for_command_response(s)
        elif command == 'mkd' and len(rawCommmand.split()) == 2:
            self.send_MKD_req(s, rawCommmand.split()[1])
            self.wait_for_command_response(s)
        elif command == 'del' and len(rawCommmand.split()) == 2:
            self.send_DEL_req(s, rawCommmand.split()[1])
            self.wait_for_command_response(s)
        elif command == 'upl' and len(rawCommmand.split()) == 2:
            fileName = rawCommmand.split()[1]
            if not os.path.isfile(fileName):
                print("file not found")
                return
            self.send_UPL_req(s, rawCommmand.split()[1])
            if self.wait_for_command_response(s):
                uploadHandler.execute_upload_protocol(fileName, s)
        elif command == 'dnl' and len(rawCommmand.split()) == 2:
            fileName = rawCommmand.split()[1]
            self.send_DNL_req(s, fileName)
            if self.wait_for_command_response(s):
                downloadHandler.execute_download_protocol(fileName, self.latestFilehash, s)
        else:
            print("Please enter a valid command")