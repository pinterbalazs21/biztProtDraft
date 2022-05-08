from protocols.common.closeConnectionException import CloseConnectionException
from protocols.common.utils import *
import os
import base64

class ServerCommandsProtocol:
    def __init__(self, MTP, userRoot):
        self.userRoot = userRoot
        self.currentWD = userRoot
        self.MTP = MTP

    # creates command response body
    def __create_command_res(self, type, *args):
        response = type + "\n" + self.latestHash
        if args:  # has at least 1 param
            for resp in args:
                response = response + "\n" + resp
        return response.encode("utf-8")

    def encrypt_command_res(self, s, commandType, *args):
        payload = self.__create_command_res(commandType, *args)
        response = self.MTP.encrypt_and_auth(b'\x01\x10', payload)
        s.sendall(response)

   #def decrypt_command_msg(self, rawMSG):
   #    decryptedPayload = self.MTP.decrypt_and_verify(rawMSG).decode("utf-8")
   #    commandList = decryptedPayload.split("\n")
   #    commandTypeStr = commandList[0]
   #    args = ()
   #    if len(commandList) > 1:
   #        args = commandList[1:]
   #    return commandTypeStr, args, decryptedPayload

    def accept_command_req(self, s):
        header, msg = self.MTP.wait_for_message(s)
        msgType = header[2:4]
        if msgType != b'\x01\x00':
            raise CloseConnectionException("Wrong message type: " + msgType + "instead of 01 00")
        rawMSG = header + msg
        decryptedPayload = self.MTP.decrypt_and_verify(rawMSG).decode("utf-8")
        commandList = decryptedPayload.split("\n")
        command = commandList[0]
        args = ()
        if len(commandList) > 1:
            args = commandList[1:]
        self.latestHash = get_hash(decryptedPayload.encode("utf-8"))
        print("payload: ", self.latestHash)
        print("payload hex: ", self.latestHash)
        return command, args


    def handle_command_req(self, command, args, conn, downloadHandler, uploadHandler):
        """
        Recieves command, if ok: execute command & success/accept response. otherwise: failure or reject response
        """
        # args tuple!
        if command == "pwd": # 0 args
            print("command request: pwd")
            try:
                self.encrypt_command_res(conn, command, 'success', self.currentWD)
            except CloseConnectionException as ce:
                raise ce
            except Exception as error:
                self.encrypt_command_res(conn, command, 'failure', str(error))
        elif command == "lst": # 0 args
            print("command request: lst")
            try:
                if not check_dir(self.userRoot, self.currentWD):
                    raise Exception('Access denied!') # not possible to reach this
                lstResult = os.listdir(self.currentWD)
                lstStr = "\n".join(lstResult)
                if not lstStr: # empty dir handling
                    lstStr = ""
                encodedStr = base64.b64encode(lstStr.encode('utf-8')).decode('utf-8')
                self.encrypt_command_res(conn, command, 'success', encodedStr)
                print("Sending success")
            except CloseConnectionException as ce:
                raise ce
            except Exception as error:
                self.encrypt_command_res(conn, command, 'failure', str(error))
        elif command == "chd": # 1 args
            print("command request: chd")
            try:
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                if not check_dir(self.userRoot, path):
                    raise Exception('Access denied! Moving outside the root directory not allowed!')
                if not os.path.exists(path) or os.path.isfile(path):
                    raise Exception('Folder does not exist')
                self.currentWD = path
                self.encrypt_command_res(conn, command, 'success')
            except CloseConnectionException as ce:
                raise ce
            except Exception as error:
                self.encrypt_command_res(conn, command, 'failure', str(error))
        elif command == "mkd":  # 1 args
            print("command request: mkd")
            try:
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                if not check_dir(self.userRoot, path):
                    raise Exception('File is outside root directory of user, access denied')
                os.mkdir(path)
                self.encrypt_command_res(conn, command, 'success')
            except CloseConnectionException as ce:
                raise ce
            except Exception as error:
                self.encrypt_command_res(conn, command, 'failure', str(error))
        elif command == "del":  # 1 args
            print("command request: del")
            try:
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                print(path)
                if not check_dir(self.userRoot, path):
                    raise Exception('File is outside root directory of user, access denied')

                if os.path.exists(path) and os.path.isfile(path):
                    os.remove(path)
                elif os.path.exists(path) and len(os.listdir(path)) == 0:
                    os.rmdir(path)
                else:
                    raise Exception('File or folder does not exist (or not empty)')
                self.encrypt_command_res(conn, command, 'success')
            except CloseConnectionException as ce:
                raise ce
            except Exception as error:
                print("Exception " + str(error))
                self.encrypt_command_res(conn, command, 'failure', str(error))
        elif command == "upl":  # 3 args
            try:
                print("command request: upl")
                size = int(args[1]) # TODO ezekkel semmit nem kell csinálni - spec szerint ja, érdekes
                hash = args[2]
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                if not check_dir(self.userRoot, path):
                    raise Exception('File is outside root directory of user, access denied')
                if os.path.isfile(path):
                    raise Exception('File with the name "' + path + '" already exists!')
                print("File will be uploaded to: ", path)
                self.encrypt_command_res(conn, command, 'accept')
                uploadHandler.execute_upload_protocol(path, conn)
            except CloseConnectionException as ce:
                raise ce
            except Exception as error:
                print("Exception " + str(error))
                self.encrypt_command_res(conn, command, 'reject', str(error))
        elif command == "dnl":  # 1 args
            print("command request: dnl")
            try:
                path = os.path.normpath(os.path.join(self.currentWD, args[0]))
                if not check_dir(self.userRoot, path):
                    raise Exception('File is outside root directory of user, access denied')
                print(path)
                print("File will be downloaded from: ", path)
                if os.path.exists(path) and os.path.isfile(path):
                    fileHash, size = get_file_info(path)
                    print("file size = " + str(size))
                    if size == 0:
                        raise Exception('File is empty')
                    self.encrypt_command_res(conn, command, 'accept', str(size), fileHash)
                    downloadHandler.execute_download_protocol(path, conn)
                else:
                    print("Exception, file does not exist")
                    raise Exception('File does not exist')
            except CloseConnectionException as ce:
                raise ce
            except Exception as error:
                self.encrypt_command_res(conn, command, 'reject', str(error))