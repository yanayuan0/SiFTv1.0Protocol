# siftcmd.py (Client)

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

    # Builds and sends command to server (to be used by the client)
    def send_command(self, cmd_req_struct):
        # Building a command request
        msg_payload = self.build_command_req(cmd_req_struct)

        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload.decode('utf-8'))
            print('------------------------------------------')

        # Compute hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # Try to send command request
        try:
            self.mtp.send_msg(self.mtp.type_command_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error('Unable to send command request --> ' + e.err_msg)

        # Try to receive a command response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_CMD_Error('Unable to receive command response --> ' + e.err_msg)

        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload.decode('utf-8'))
            print('------------------------------------------')

        if msg_type != self.mtp.type_command_res:
            raise SiFT_CMD_Error('Command response expected, but received something else')

        # Process command response
        try:
            cmd_res_struct = self.parse_command_res(msg_payload)
        except:
            raise SiFT_CMD_Error('Parsing command response failed')

        # Verify request_hash received in the command response
        if cmd_res_struct['request_hash'] != request_hash:
            raise SiFT_CMD_Error('Verification of command response failed')

        return cmd_res_struct

    # The rest of the methods (upload and download) are handled in client.py
