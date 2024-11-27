import sys, threading, socket, os
from Crypto.PublicKey import RSA
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error
from siftprotocols.siftupl import SiFT_UPL, SiFT_UPL_Error
from siftprotocols.siftdnl import SiFT_DNL, SiFT_DNL_Error

class Server:
    def __init__(self):
        # ----------- CONFIG -------------
        self.server_ip = '127.0.0.1'  # localhost
        self.server_port = 5152
        self.server_rootdir = './users/'
        self.server_usersfile = 'users.txt'
        self.server_usersfile_coding = 'utf-8'
        self.server_usersfile_rec_delimiter = '\n'
        self.server_usersfile_fld_delimiter = ':'
        # --------------------------------

        # Load server's private key
        try:
            with open('server_private_key.pem', 'rb') as f:
                self.server_private_key = RSA.import_key(f.read())
                # print("server_private_key: ", str(self.server_private_key))
        except Exception as e:
            print('Error loading server private key:', str(e))
            sys.exit(1)

        # Load users
        self.users = self.load_users()

        # Set up server socket and start listening
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(5)
        print('Server listening on ' + self.server_ip + ':' + str(self.server_port))

        # Start accepting connections
        self.accept_connections()

    def load_users(self):
        users = {}
        try:
            with open(self.server_usersfile, 'rb') as f:
                allrecords = f.read().decode(self.server_usersfile_coding)
            records = allrecords.strip().split(self.server_usersfile_rec_delimiter)
            for r in records:
                if not r.strip():
                    continue
                fields = r.strip().split(self.server_usersfile_fld_delimiter)
                if len(fields) < 5:
                    print('Invalid user record:', r)
                    continue
                username = fields[0]
                usr_struct = {
                    'pwdhash': bytes.fromhex(fields[1]),
                    'icount': int(fields[2]),
                    'salt': bytes.fromhex(fields[3]),
                    'rootdir': fields[4],
                }
                users[username] = usr_struct
        except Exception as e:
            print('Error loading users:', str(e))
            sys.exit(1)
        return users


    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print('New client connection from', addr[0] + ':' + str(addr[1]))
            threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()

    def handle_client(self, client_socket, addr):
        mtp = SiFT_MTP(client_socket, is_server=True)
        mtp.set_server_private_key(self.server_private_key)
        loginp = SiFT_LOGIN(mtp)
        loginp.set_server_users(self.users)

        # Handle login
        try:
            username = loginp.handle_login_server()
        except SiFT_LOGIN_Error as e:
            print('Login error from', addr[0] + ':' + str(addr[1]), '-', e.err_msg)
            client_socket.close()
            return
        print('User', username, 'logged in from', addr[0] + ':' + str(addr[1]))

        # Handle commands
        cmdp = SiFT_CMD(mtp)
        cmdp.set_server_rootdir(self.server_rootdir)
        cmdp.set_user_rootdir(self.users[username]['rootdir'])
        uplp = SiFT_UPL(mtp)
        dnlp = SiFT_DNL(mtp)

        # while True:
        #     try:
        #         cmd_type, cmd_data = mtp.receive_msg()
        #         print("command type: ", str(cmd_type))
        #         if cmd_type == cmdp.type_command_req:
        #             cmdp.receive_command(cmd_data)
        #         elif cmd_type == uplp.type_upload_req:
        #             uplp.handle_upload_server(cmd_data)
        #         elif cmd_type == dnlp.type_download_req:
        #             dnlp.handle_download_server(cmd_data)
        #         else:
        #             print('Unknown message type received:', cmd_type.hex())
        #     except (SiFT_MTP_Error, SiFT_CMD_Error, SiFT_UPL_Error, SiFT_DNL_Error) as e:
        #         print('Error handling client', addr[0] + ':' + str(addr[1]), '-', str(e))
        #         client_socket.close()
        #         return

        while True:
            try:
                cmdp.receive_command()
            except SiFT_CMD_Error as e:
                print('SiFT_CMD_Error: ' + e.err_msg)
                print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
                client_socket.close()
                return

# --------------------------------------
if __name__ == '__main__':
    Server()