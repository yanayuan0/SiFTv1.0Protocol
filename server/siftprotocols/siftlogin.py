# siftlogin.py (Server)

import time
import os
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.PublicKey import RSA
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
        self.server_users = None
        self.server_private_key = None

    # Sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users

    def set_server_private_key(self, private_key):
        self.server_private_key = private_key

    # Parses a login request into a dictionary
    def parse_login_req(self, login_req):
        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        print('Parsed login request fields:', login_req_fields)
        login_req_struct = {}
        login_req_struct['timestamp'] = int(login_req_fields[0])
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = bytes.fromhex(login_req_fields[3])
        return login_req_struct

    # Builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        login_res_str = login_res_struct['request_hash']
        login_res_str += self.delimiter + login_res_struct['server_random'].hex()
        return login_res_str.encode(self.coding)

    # Checks correctness of a provided password
    def check_password(self, pwd, usr_struct):
        print('Checking password:', repr(pwd))
        print('Using salt:', usr_struct['salt'])
        print('Using iteration count:', usr_struct['icount'])
        pwdhash = PBKDF2(pwd, usr_struct['salt'], dkLen=len(usr_struct['pwdhash']),
                         count=usr_struct['icount'], hmac_hash_module=SHA256)
        print('Computed pwdhash:', pwdhash.hex())
        print('Stored pwdhash:', usr_struct['pwdhash'].hex())
        return pwdhash == usr_struct['pwdhash']

    # Handles login process (to be used by the server)
    def handle_login_server(self):
        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')
        # if not self.server_private_key:
        #     raise SiFT_LOGIN_Error('Server private key is required for login')

        # Trying to receive a login request
        try:
            msg_type, msg_payload_decrypted = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming decrypted payload (' + str(len(msg_payload_decrypted)) + ' bytes):')
            print(msg_payload_decrypted.decode(self.coding))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # Use the decrypted message payload
        msg_payload = msg_payload_decrypted

        # Processing login request
        login_req_struct = self.parse_login_req(msg_payload)

        # Checking timestamp
        current_time = time.time_ns()
        acceptance_window = 2 * 1e9  # 2 seconds in nanoseconds
        if abs(current_time - login_req_struct['timestamp']) > acceptance_window / 2:
            raise SiFT_LOGIN_Error('Timestamp verification failed')

        # Computing hash of received plaintext login request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.hexdigest()

        # Checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'],
                                       self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unknown user attempted to log in')

        # Generating server_random
        server_random = os.urandom(16)

        # Building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        login_res_struct['server_random'] = server_random
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + ' bytes):')
            print(msg_payload.decode(self.coding))
            print('------------------------------------------')
        # DEBUG 

        # Sending login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # Computing final transfer key
        initial_key_material = login_req_struct['client_random'] + server_random
        salt = bytes.fromhex(request_hash)  # Convert hex string back to bytes
        final_transfer_key = HKDF(initial_key_material, 32, salt, SHA256)

        # Set the transfer key in MTP
        self.mtp.set_transfer_key(final_transfer_key)

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 

        return login_req_struct['username']
