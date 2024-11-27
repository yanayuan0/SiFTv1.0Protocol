import time
import os
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_LOGIN_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):
        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_public_key = None  # Will be set later

    # Method to set the server's public key
    def set_server_public_key(self, public_key):
        self.server_public_key = public_key
        self.mtp.set_server_public_key(public_key)  # Set in MTP

    # Builds a login request from a dictionary
    def build_login_req(self, login_req_struct):
        login_req_str = str(login_req_struct['timestamp'])
        login_req_str += self.delimiter + login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password']
        login_req_str += self.delimiter + login_req_struct['client_random'].hex()
        return login_req_str.encode(self.coding)

    # Parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = login_res_fields[0]
        login_res_struct['server_random'] = bytes.fromhex(login_res_fields[1])
        return login_res_struct

    # Handles login process (to be used by the client)
    def handle_login_client(self, username, password):
        if not self.server_public_key:
            raise SiFT_LOGIN_Error('Server public key is required for login')

        # Building a login request
        login_req_struct = {}
        login_req_struct['timestamp'] = time.time_ns()
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        login_req_struct['client_random'] = os.urandom(16)
        msg_payload = self.build_login_req(login_req_struct)

        # Computing hash of the plaintext login request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.hexdigest()

        # DEBUG
        if self.DEBUG:
            print('Outgoing login request payload (' + str(len(msg_payload)) + ' bytes):')
            print(msg_payload.decode('utf-8'))
            print('------------------------------------------')

        # Trying to send login request via MTP
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # Trying to receive a login response via MTP
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Incoming login response payload (' + str(len(msg_payload)) + ' bytes):')
            print(msg_payload.decode('utf-8'))
            print('------------------------------------------')

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # Processing login response
        login_res_struct = self.parse_login_res(msg_payload)

        # Checking request_hash received in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

        # Derive transfer key using MTP's method
        self.mtp.derive_transfer_key(
            login_req_struct['client_random'],
            login_res_struct['server_random'],
            request_hash
        )

        # DEBUG
        if self.DEBUG:
            print('User ' + username + ' logged in')
            print('Final transfer key:', self.mtp.transfer_key.hex())
            print('------------------------------------------')

        return username