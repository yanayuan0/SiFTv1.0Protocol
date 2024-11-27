# siftcmd.py (Server)

import os
from base64 import b64encode, b64decode
from Crypto.Hash import SHA256
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftprotocols.siftupl import SiFT_UPL, SiFT_UPL_Error
from siftprotocols.siftdnl import SiFT_DNL, SiFT_DNL_Error

class SiFT_CMD_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_CMD:
    def __init__(self, mtp):
        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.cmd_pwd = 'pwd'
        self.cmd_lst = 'lst'
        self.cmd_chd = 'chd'
        self.cmd_mkd = 'mkd'
        self.cmd_del = 'del'
        self.cmd_upl = 'upl'
        self.cmd_dnl = 'dnl'
        self.commands = (
            self.cmd_pwd, self.cmd_lst, self.cmd_chd,
            self.cmd_mkd, self.cmd_del,
            self.cmd_upl, self.cmd_dnl
        )
        self.res_success = 'success'
        self.res_failure = 'failure'
        self.res_accept = 'accept'
        self.res_reject = 'reject'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_rootdir = None
        self.user_rootdir = None
        self.current_dir = []
        self.filesize_limit = 2 ** 16

    # Sets the root directory (to be used by the server)
    def set_server_rootdir(self, server_rootdir):
        self.server_rootdir = server_rootdir

    # Sets the root directory of the user (to be used by the server)
    def set_user_rootdir(self, user_rootdir):
        self.user_rootdir = user_rootdir
        if self.DEBUG:
            print('User root directory is set to ' + self.user_rootdir)

    # Sets file size limit for uploads
    def set_filesize_limit(self, limit):
        self.filesize_limit = limit

    # Builds a command request from a dictionary
    def build_command_req(self, cmd_req_struct):
        cmd_req_str = cmd_req_struct['command']

        if cmd_req_struct['command'] in [self.cmd_chd, self.cmd_mkd, self.cmd_del]:
            cmd_req_str += self.delimiter + cmd_req_struct['param_1']

        elif cmd_req_struct['command'] == self.cmd_upl:
            cmd_req_str += self.delimiter + cmd_req_struct['param_1']
            cmd_req_str += self.delimiter + str(cmd_req_struct['param_2'])
            cmd_req_str += self.delimiter + cmd_req_struct['param_3'].hex()

        elif cmd_req_struct['command'] == self.cmd_dnl:
            cmd_req_str += self.delimiter + cmd_req_struct['param_1']

        return cmd_req_str.encode(self.coding)

    # Parses a command request into a dictionary
    def parse_command_req(self, cmd_req):
        cmd_req_fields = cmd_req.decode(self.coding).split(self.delimiter)
        cmd_req_struct = {}
        cmd_req_struct['command'] = cmd_req_fields[0]

        if cmd_req_struct['command'] in [self.cmd_chd, self.cmd_mkd, self.cmd_del]:
            cmd_req_struct['param_1'] = cmd_req_fields[1]

        elif cmd_req_struct['command'] == self.cmd_upl:
            cmd_req_struct['param_1'] = cmd_req_fields[1]
            cmd_req_struct['param_2'] = int(cmd_req_fields[2])
            cmd_req_struct['param_3'] = bytes.fromhex(cmd_req_fields[3])

        elif cmd_req_struct['command'] == self.cmd_dnl:
            cmd_req_struct['param_1'] = cmd_req_fields[1]

        return cmd_req_struct

    # Builds a command response from a dictionary
    def build_command_res(self, cmd_res_struct):
        cmd_res_str = cmd_res_struct['command']
        cmd_res_str += self.delimiter + cmd_res_struct['request_hash'].hex()
        cmd_res_str += self.delimiter + cmd_res_struct['result_1']

        if cmd_res_struct['command'] == self.cmd_pwd:
            cmd_res_str += self.delimiter + cmd_res_struct['result_2']

        elif cmd_res_struct['command'] == self.cmd_lst:
            if cmd_res_struct['result_1'] == self.res_failure:
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']
            else:
                cmd_res_str += self.delimiter + b64encode(
                    cmd_res_struct['result_2'].encode(self.coding)
                ).decode(self.coding)

        elif cmd_res_struct['command'] in [self.cmd_chd, self.cmd_mkd, self.cmd_del]:
            if cmd_res_struct['result_1'] == self.res_failure:
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']

        elif cmd_res_struct['command'] == self.cmd_upl:
            if cmd_res_struct['result_1'] == self.res_reject:
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']

        elif cmd_res_struct['command'] == self.cmd_dnl:
            if cmd_res_struct['result_1'] == self.res_reject:
                cmd_res_str += self.delimiter + cmd_res_struct['result_2']
            else:
                cmd_res_str += self.delimiter + str(cmd_res_struct['result_2'])
                cmd_res_str += self.delimiter + cmd_res_struct['result_3'].hex()

        return cmd_res_str.encode(self.coding)

    # Parses a command response into a dictionary
    def parse_command_res(self, cmd_res):
        cmd_res_fields = cmd_res.decode(self.coding).split(self.delimiter)
        cmd_res_struct = {}
        cmd_res_struct['command'] = cmd_res_fields[0]
        cmd_res_struct['request_hash'] = bytes.fromhex(cmd_res_fields[1])
        cmd_res_struct['result_1'] = cmd_res_fields[2]

        if cmd_res_struct['command'] == self.cmd_pwd:
            cmd_res_struct['result_2'] = cmd_res_fields[3]

        elif cmd_res_struct['command'] == self.cmd_lst:
            if cmd_res_struct['result_1'] == self.res_failure:
                cmd_res_struct['result_2'] = cmd_res_fields[3]
            else:
                cmd_res_struct['result_2'] = b64decode(
                    cmd_res_fields[3]
                ).decode(self.coding)

        elif cmd_res_struct['command'] in [self.cmd_chd, self.cmd_mkd, self.cmd_del]:
            if cmd_res_struct['result_1'] == self.res_failure:
                cmd_res_struct['result_2'] = cmd_res_fields[3]

        elif cmd_res_struct['command'] == self.cmd_upl:
            if cmd_res_struct['result_1'] == self.res_reject:
                cmd_res_struct['result_2'] = cmd_res_fields[3]

        elif cmd_res_struct['command'] == self.cmd_dnl:
            if cmd_res_struct['result_1'] == self.res_reject:
                cmd_res_struct['result_2'] = cmd_res_fields[3]
            else:
                cmd_res_struct['result_2'] = int(cmd_res_fields[3])
                cmd_res_struct['result_3'] = bytes.fromhex(cmd_res_fields[4])

        return cmd_res_struct

    # Handles incoming command (to be used by the server)
    def receive_command(self):
        if not self.server_rootdir or not self.user_rootdir:
            raise SiFT_CMD_Error(
                'Root directory must be set before any file operations'
            )

        # Try to receive a command request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error(
                'Unable to receive command request --> ' + e.err_msg
            )

        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload.decode('utf-8'))
            print('------------------------------------------')

        if msg_type != self.mtp.type_command_req:
            raise SiFT_CMD_Error(
                'Command request expected, but received something else'
            )

        # Compute hash of request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # Process command request
        try:
            cmd_req_struct = self.parse_command_req(msg_payload)
        except:
            raise SiFT_CMD_Error('Parsing command request failed')

        if cmd_req_struct['command'] not in self.commands:
            raise SiFT_CMD_Error('Unexpected command received')

        # Execute command
        cmd_res_struct = self.exec_cmd(cmd_req_struct, request_hash)

        # Build a command response
        msg_payload = self.build_command_res(cmd_res_struct)

        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload.decode('utf-8'))
            print('------------------------------------------')

        # Try to send command response
        try:
            self.mtp.send_msg(self.mtp.type_command_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error(
                'Unable to send command response --> ' + e.err_msg
            )

        # If upload command was accepted, then execute upload
        if (cmd_res_struct['command'] == self.cmd_upl and
                cmd_res_struct['result_1'] == self.res_accept):
            try:
                self.exec_upl(cmd_req_struct['param_1'])
            except SiFT_UPL_Error as e:
                raise SiFT_CMD_Error('Upload Error: ' + e.err_msg)

        # If download command was accepted, then execute download
        if (cmd_res_struct['command'] == self.cmd_dnl and
                cmd_res_struct['result_1'] == self.res_accept):
            try:
                self.exec_dnl(cmd_req_struct['param_1'])
            except SiFT_DNL_Error as e:
                raise SiFT_CMD_Error('Download Error: ' + e.err_msg)

    # Builds and sends command to server (to be used by the client)
    def send_command(self, cmd_req_struct):
        # This method is not used on the server side
        pass

    # -----------------------------------------------------------------------------------------
    # File operations on the server
    # -----------------------------------------------------------------------------------------

    # Checks file or directory name for special characters
    def check_fdname(self, fdname):
        if not fdname:
            return False
        if fdname.startswith('.') or '..' in fdname:
            return False
        allowed_chars = set(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.'
        )
        return all(c in allowed_chars for c in fdname)

    # Execute command
    def exec_cmd(self, cmd_req_struct, request_hash):
        cmd_res_struct = {}
        cmd_res_struct['command'] = cmd_req_struct['command']
        cmd_res_struct['request_hash'] = request_hash

        # Base path
        base_path = os.path.join(
            self.server_rootdir, self.user_rootdir, *self.current_dir
        )
        base_path = os.path.normpath(base_path)

        # pwd
        if cmd_req_struct['command'] == self.cmd_pwd:
            cmd_res_struct['result_1'] = self.res_success
            cmd_res_struct['result_2'] = '/'.join(self.current_dir) + '/'

        # lst
        elif cmd_req_struct['command'] == self.cmd_lst:
            if not os.path.exists(base_path):
                cmd_res_struct['result_1'] = self.res_failure
                cmd_res_struct['result_2'] = 'Directory does not exist'
            else:
                dirlist_str = ''
                with os.scandir(base_path) as dirlist:
                    for f in dirlist:
                        if not f.name.startswith('.'):
                            if f.is_file():
                                dirlist_str += f.name + '\n'
                            elif f.is_dir():
                                dirlist_str += f.name + '/\n'
                dirlist_str = dirlist_str.rstrip('\n')
                cmd_res_struct['result_1'] = self.res_success
                cmd_res_struct['result_2'] = dirlist_str

        # chd
        elif cmd_req_struct['command'] == self.cmd_chd:
            dirname = cmd_req_struct['param_1']
            if dirname == '..':
                if not self.current_dir:
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = (
                        'Cannot change to directory outside of the user root directory'
                    )
                else:
                    self.current_dir.pop()
                    cmd_res_struct['result_1'] = self.res_success
            else:
                if not self.check_fdname(dirname):
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = (
                        'Invalid directory name'
                    )
                else:
                    new_path = os.path.join(base_path, dirname)
                    new_path = os.path.normpath(new_path)
                    if not new_path.startswith(base_path):
                        cmd_res_struct['result_1'] = self.res_failure
                        cmd_res_struct['result_2'] = (
                            'Access denied: Cannot access outside your root directory'
                        )
                    elif not os.path.exists(new_path):
                        cmd_res_struct['result_1'] = self.res_failure
                        cmd_res_struct['result_2'] = 'Directory does not exist'
                    else:
                        self.current_dir.append(dirname)
                        cmd_res_struct['result_1'] = self.res_success

        # mkd
        elif cmd_req_struct['command'] == self.cmd_mkd:
            dirname = cmd_req_struct['param_1']
            if not self.check_fdname(dirname):
                cmd_res_struct['result_1'] = self.res_failure
                cmd_res_struct['result_2'] = 'Invalid directory name'
            else:
                new_path = os.path.join(base_path, dirname)
                new_path = os.path.normpath(new_path)
                if not new_path.startswith(base_path):
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = (
                        'Access denied: Cannot create directory outside your root directory'
                    )
                elif os.path.exists(new_path):
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = 'Directory already exists'
                else:
                    try:
                        os.mkdir(new_path)
                    except Exception as e:
                        cmd_res_struct['result_1'] = self.res_failure
                        cmd_res_struct['result_2'] = (
                            'Creating directory failed: ' + str(e)
                        )
                    else:
                        cmd_res_struct['result_1'] = self.res_success

        # del
        elif cmd_req_struct['command'] == self.cmd_del:
            fdname = cmd_req_struct['param_1']
            if not self.check_fdname(fdname):
                cmd_res_struct['result_1'] = self.res_failure
                cmd_res_struct['result_2'] = 'Invalid file or directory name'
            else:
                target_path = os.path.join(base_path, fdname)
                target_path = os.path.normpath(target_path)
                if not target_path.startswith(base_path):
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = (
                        'Access denied: Cannot delete outside your root directory'
                    )
                elif not os.path.exists(target_path):
                    cmd_res_struct['result_1'] = self.res_failure
                    cmd_res_struct['result_2'] = (
                        'File or directory does not exist'
                    )
                else:
                    try:
                        if os.path.isdir(target_path):
                            os.rmdir(target_path)
                        else:
                            os.remove(target_path)
                    except Exception as e:
                        cmd_res_struct['result_1'] = self.res_failure
                        cmd_res_struct['result_2'] = (
                            'Removing failed: ' + str(e)
                        )
                    else:
                        cmd_res_struct['result_1'] = self.res_success

        # upl
        elif cmd_req_struct['command'] == self.cmd_upl:
            filename = cmd_req_struct['param_1']
            filesize = cmd_req_struct['param_2']
            filehash = cmd_req_struct['param_3']
            if not self.check_fdname(filename):
                cmd_res_struct['result_1'] = self.res_reject
                cmd_res_struct['result_2'] = 'Invalid file name'
            elif filesize > self.filesize_limit:
                cmd_res_struct['result_1'] = self.res_reject
                cmd_res_struct['result_2'] = 'File is too large'
            else:
                cmd_res_struct['result_1'] = self.res_accept

        # dnl
        elif cmd_req_struct['command'] == self.cmd_dnl:
            filename = cmd_req_struct['param_1']
            if not self.check_fdname(filename):
                cmd_res_struct['result_1'] = self.res_reject
                cmd_res_struct['result_2'] = 'Invalid file name'
            else:
                file_path = os.path.join(base_path, filename)
                file_path = os.path.normpath(file_path)
                if not file_path.startswith(base_path):
                    cmd_res_struct['result_1'] = self.res_reject
                    cmd_res_struct['result_2'] = (
                        'Access denied: Cannot download outside your root directory'
                    )
                elif not os.path.exists(file_path):
                    cmd_res_struct['result_1'] = self.res_reject
                    cmd_res_struct['result_2'] = 'File does not exist'
                elif not os.path.isfile(file_path):
                    cmd_res_struct['result_1'] = self.res_reject
                    cmd_res_struct['result_2'] = 'Only file download is supported'
                else:
                    with open(file_path, 'rb') as f:
                        hash_fn = SHA256.new()
                        file_size = 0
                        while True:
                            chunk = f.read(1024)
                            if not chunk:
                                break
                            file_size += len(chunk)
                            hash_fn.update(chunk)
                        file_hash = hash_fn.digest()
                    cmd_res_struct['result_1'] = self.res_accept
                    cmd_res_struct['result_2'] = file_size
                    cmd_res_struct['result_3'] = file_hash

        return cmd_res_struct

    # Execute upload
    def exec_upl(self, filename):
        if not self.check_fdname(filename):
            raise SiFT_UPL_Error(
                'Invalid file name for upload'
            )
        else:
            base_path = os.path.join(
                self.server_rootdir, self.user_rootdir, *self.current_dir
            )
            base_path = os.path.normpath(base_path)
            file_path = os.path.join(base_path, filename)
            file_path = os.path.normpath(file_path)
            if not file_path.startswith(base_path):
                raise SiFT_UPL_Error(
                    'Access denied: Cannot upload outside your root directory'
                )
            uplp = SiFT_UPL(self.mtp)
            try:
                uplp.handle_upload_server(file_path)
            except SiFT_UPL_Error as e:
                raise SiFT_UPL_Error(e.err_msg)

    # Execute download
    def exec_dnl(self, filename):
        if not self.check_fdname(filename):
            raise SiFT_DNL_Error('Invalid file name for download')
        else:
            base_path = os.path.join(
                self.server_rootdir, self.user_rootdir, *self.current_dir
            )
            base_path = os.path.normpath(base_path)
            file_path = os.path.join(base_path, filename)
            file_path = os.path.normpath(file_path)
            if not file_path.startswith(base_path):
                raise SiFT_DNL_Error(
                    'Access denied: Cannot download outside your root directory'
                )
            if not os.path.exists(file_path):
                raise SiFT_DNL_Error('File does not exist')
            if not os.path.isfile(file_path):
                raise SiFT_DNL_Error('Only file download is supported')
            dnlp = SiFT_DNL(self.mtp)
            try:
                dnlp.handle_download_server(file_path)
            except SiFT_DNL_Error as e:
                raise SiFT_DNL_Error(e.err_msg)
