import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF  # Updated import

class SiFT_MTP_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
    def __init__(self, peer_socket, is_server=False):
        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.version_major = 1
        self.version_minor = 0
        self.msg_hdr_ver = b'\x01\x00'  # Version 1.0
        self.size_msg_hdr = 16  # 16-byte header for v1.0
        self.size_msg_hdr_ver = 2  # Version field size
        self.size_msg_hdr_typ = 2  # Type field size
        self.size_msg_hdr_len = 2  # Length field size
        self.size_msg_hdr_sqn = 2  # Sequence number field size
        self.size_msg_hdr_rnd = 6  # Random field size
        self.size_msg_hdr_rsv = 2  # Reserved field size
        self.size_mac = 12  # MAC size for GCM (set to 12 bytes)
        self.size_etk = 256  # Encrypted temporary key size (RSA 2048 bits)

        self.type_login_req =    b'\x00\x00'
        self.type_login_res =    b'\x00\x10'
        self.type_command_req =  b'\x01\x00'
        self.type_command_res =  b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res =   b'\x02\x10'
        self.type_dnload_req =   b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'

        self.msg_types = (
            self.type_login_req, self.type_login_res,
            self.type_command_req, self.type_command_res,
            self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
            self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1
        )

        # --------- STATE ------------
        self.peer_socket = peer_socket
        self.is_server = is_server
        self.transfer_key = None
        self.temporary_key = None
        self.send_seq_num = 1
        self.recv_seq_num = 0
        self.server_public_key = None  # Set on the client side
        self.server_private_key = None  # Set on the server side

    def set_transfer_key(self, key):
        self.transfer_key = key

    def set_server_public_key(self, public_key):
        self.server_public_key = public_key

    def set_server_private_key(self, private_key):
        self.server_private_key = private_key

    def parse_msg_header(self, msg_hdr):
        parsed_msg_hdr, i = {}, 0
        parsed_msg_hdr['ver'], i = msg_hdr[i:i+2], i+2  # Version
        parsed_msg_hdr['typ'], i = msg_hdr[i:i+2], i+2  # Type
        parsed_msg_hdr['len'], i = msg_hdr[i:i+2], i+2  # Length
        parsed_msg_hdr['sqn'], i = msg_hdr[i:i+2], i+2  # Sequence number
        parsed_msg_hdr['rnd'], i = msg_hdr[i:i+6], i+6  # Random
        parsed_msg_hdr['rsv'] = msg_hdr[i:i+2]          # Reserved
        return parsed_msg_hdr

    def receive_bytes(self, n):
        bytes_received = b''
        bytes_count = 0
        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n - bytes_count)
            except:
                raise SiFT_MTP_Error('Unable to receive via peer socket')
            if not chunk:
                raise SiFT_MTP_Error('Connection with peer is broken')
            bytes_received += chunk
            bytes_count += len(chunk)
        return bytes_received

    def receive_msg(self):
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message header received')

        parsed_msg_hdr = self.parse_msg_header(msg_hdr)

        # Verify version and message type
        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')
        if parsed_msg_hdr['typ'] not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')

        # Verify sequence number
        recv_seq = int.from_bytes(parsed_msg_hdr['sqn'], 'big')
        if recv_seq <= self.recv_seq_num:
            raise SiFT_MTP_Error('Invalid sequence number')
        # Do not update recv_seq_num yet; only after successful decryption
        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

        try:
            if parsed_msg_hdr['typ'] == self.type_login_req:
                # Special handling for login_req
                total_len = msg_len - self.size_msg_hdr
                encrypted_payload_and_mac = self.receive_bytes(total_len - self.size_etk)
                etk = self.receive_bytes(self.size_etk)
                # Decrypt etk to get tk
                if not self.is_server or self.server_private_key is None:
                    raise SiFT_MTP_Error('Server private key not set for decrypting etk')
                tk = self.rsa_decrypt(etk, self.server_private_key)
                self.temporary_key = tk
                # Decrypt payload
                nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
                cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
                cipher.update(msg_hdr)
                encrypted_payload = encrypted_payload_and_mac[:-self.size_mac]
                tag = encrypted_payload_and_mac[-self.size_mac:]
                msg_body = cipher.decrypt_and_verify(encrypted_payload, tag)
            elif parsed_msg_hdr['typ'] == self.type_login_res:
                # Use temporary key
                if self.temporary_key is None:
                    raise SiFT_MTP_Error('Temporary key not set for decrypting login_res')
                encrypted_payload_and_mac = self.receive_bytes(msg_len - self.size_msg_hdr)
                nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
                cipher = AES.new(self.temporary_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
                cipher.update(msg_hdr)
                encrypted_payload = encrypted_payload_and_mac[:-self.size_mac]
                tag = encrypted_payload_and_mac[-self.size_mac:]
                msg_body = cipher.decrypt_and_verify(encrypted_payload, tag)
            else:
                if self.transfer_key is None:
                    raise SiFT_MTP_Error('Transfer key not set for decrypting message')
                encrypted_payload_and_mac = self.receive_bytes(msg_len - self.size_msg_hdr)
                nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
                cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
                cipher.update(msg_hdr)
                encrypted_payload = encrypted_payload_and_mac[:-self.size_mac]
                tag = encrypted_payload_and_mac[-self.size_mac:]
                msg_body = cipher.decrypt_and_verify(encrypted_payload, tag)
        except ValueError:
            raise SiFT_MTP_Error('Message authentication failed')

        # Update recv_seq_num after successful decryption
        self.recv_seq_num = recv_seq

        if self.DEBUG:
            print('MTP message received (' + str(msg_len) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('BDY (' + str(len(msg_body)) + '): ')
            print(msg_body.hex())
            print('------------------------------------------')

        return parsed_msg_hdr['typ'], msg_body

    def send_bytes(self, bytes_to_send):
        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')

    def send_msg(self, msg_type, msg_payload):
        # Generate random bytes and create sequence number
        random_bytes = get_random_bytes(self.size_msg_hdr_rnd)
        sequence_number = self.send_seq_num.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
        nonce = sequence_number + random_bytes

        if msg_type == self.type_login_req:
            # Generate temporary key (tk)
            tk = get_random_bytes(32)  # 32-byte AES key
            self.temporary_key = tk
            # Encrypt payload
            cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
            # Estimate message size
            # For login_req: header + encrypted payload + tag + etk
            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac + self.size_etk
            # Build header with correct length
            msg_hdr = (
                self.msg_hdr_ver +
                msg_type +
                msg_size.to_bytes(self.size_msg_hdr_len, 'big') +
                sequence_number +
                random_bytes +
                b'\x00\x00'
            )
            cipher.update(msg_hdr)
            encrypted_payload, tag = cipher.encrypt_and_digest(msg_payload)
            # Encrypt tk using server's RSA public key to get etk
            if self.server_public_key is None:
                raise SiFT_MTP_Error('Server public key not set for encrypting etk')
            etk = self.rsa_encrypt(tk, self.server_public_key)
            # Build final message
            full_msg = msg_hdr + encrypted_payload + tag + etk
        elif msg_type == self.type_login_res:
            if self.temporary_key is None:
                raise SiFT_MTP_Error('Temporary key not set for encrypting login_res')
            # Encrypt payload
            cipher = AES.new(self.temporary_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
            # Estimate message size
            # For login_res: header + encrypted payload + tag
            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac
            # Build header with correct length
            msg_hdr = (
                self.msg_hdr_ver +
                msg_type +
                msg_size.to_bytes(self.size_msg_hdr_len, 'big') +
                sequence_number +
                random_bytes +
                b'\x00\x00'
            )
            cipher.update(msg_hdr)
            encrypted_payload, tag = cipher.encrypt_and_digest(msg_payload)
            # Build final message
            full_msg = msg_hdr + encrypted_payload + tag
        else:
            if self.transfer_key is None:
                raise SiFT_MTP_Error('Transfer key not set for encrypting message')
            # Encrypt payload
            cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
            # Estimate message size
            # For other messages: header + encrypted payload + tag
            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac
            # Build header with correct length
            msg_hdr = (
                self.msg_hdr_ver +
                msg_type +
                msg_size.to_bytes(self.size_msg_hdr_len, 'big') +
                sequence_number +
                random_bytes +
                b'\x00\x00'
            )
            cipher.update(msg_hdr)
            encrypted_payload, tag = cipher.encrypt_and_digest(msg_payload)
            # Build final message
            full_msg = msg_hdr + encrypted_payload + tag

        if self.DEBUG:
            print('MTP message to send (' + str(msg_size) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('BDY (' + str(len(full_msg) - len(msg_hdr)) + '): ')
            print((full_msg[len(msg_hdr):]).hex())
            print('------------------------------------------')

        try:
            self.send_bytes(full_msg)
            self.send_seq_num += 1
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

    def rsa_encrypt(self, data, public_key):
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(data)

    def rsa_decrypt(self, data, private_key):
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(data)

    def derive_transfer_key(self, client_random, server_random, request_hash):
        from Crypto.Hash import SHA256
        from Crypto.Protocol.KDF import HKDF

        ikm = client_random + server_random
        salt = bytes.fromhex(request_hash)
        self.transfer_key = HKDF(
            master=ikm,
            key_len=32,
            salt=salt,
            hashmod=SHA256,
        )
        self.temporary_key = None  # Discard temporary key

    def close_connection(self):
        self.peer_socket.close()