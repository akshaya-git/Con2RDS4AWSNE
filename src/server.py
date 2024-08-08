# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0
import argparse
import socket
import sys
import json
import subprocess
import mysql.connector
import base64

# Specify your AWS region
aws_region = 'us-east-1'  # Replace with your region

# Running server you have pass port the server  will listen to. For Example:
# $ python3 /app/server.py server 5005
class VsockListener:
    # Server
    def __init__(self, conn_backlog=128):
        self.conn_backlog = conn_backlog

    def bind(self, port):
        # Bind and listen for connections on the specified port
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)

    def recv_data(self):
        """Receive data from a remote endpoint"""
        data = ''
        while True:
            (from_client, (remote_cid, remote_port)) = self.sock.accept()
            # Read 1024 bytes at a time
            try:
                data = from_client.recv(4096).decode()
                #print('data from Client:', data)
                #parse the json data sent form parent
                try:
                    data_json = json.loads(data)
                    user_enc = data_json["user"]
                    pass_enc = data_json["pass"]
                    credential = data_json["credential"]
                    try:
                        decrtpeduser = kms_call(credential, user_enc)
                        decrtpedpass = kms_call(credential, pass_enc)
                        print("decrtpeduser ---- ",decrtpeduser)
                        print("decrtpedpass ---- ",decrtpedpass)
                    except Exception as e:
                        msg = "exception happened calling kms binary: {}".format(e)
                        print(msg)                        
                except json.JSONDecodeError as e:
                    print(f"Failed to parse JSON: {e}")

                #code to connect to RDS and get the data starts  
                # Connect to the database
                cnx = mysql.connector.connect(
                host="[Enter MySql Endpoint]",
                database="[Database Name]",
                port=3306,
                user=decrtpeduser,
                password=decrtpedpass
                )
                # Execute a query
                cur = cnx.cursor()
                query = "SELECT * FROM Persons where SSN = 123456789" #Make sure the query corresponds to the table created in RDS
                cur.execute(query)
                row = cur.fetchall()
                print('Data Sample from RDS: ',row)
                
                #
                # ---------Add the custom logic here to process and detect the presence of sensitive data in RDs table-------
                #
                
                # Send back the response                 
                from_client.send(str(row).encode())
                from_client.close()
                print("Client call closed")
            except Exception as ex:
                print(ex)

def server_handler(args):
    server = VsockListener()
    server.bind(args.port)
    print("Started listening to port : ",str(args.port))
    server.recv_data()

 # kms client method
def kms_call(credential, ciphertext):
    aws_access_key_id = credential["AccessKeyId"]
    aws_secret_access_key = credential["SecretAccessKey"]
    aws_session_token = credential["Token"]
    subprocess_args = [
        "/kmstool_enclave_cli",
        "decrypt",
        "--region",
        aws_region,
        "--proxy-port",
        "7000",
        "--aws-access-key-id",
        aws_access_key_id,
        "--aws-secret-access-key",
        aws_secret_access_key,
        "--aws-session-token",
        aws_session_token,
        "--ciphertext",
        ciphertext,
    ]
    print("subprocess args: {}".format(subprocess_args))
    proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Read the standard output and standard error
    try:
        # Retrieve the secret
        stdout, stderr = proc.communicate()
    except Exception as e:
        print(f"Error calling KMS cli: {e}")

    #stdout, stderr = proc.communicate()
    # Decode the bytes to string and print the output
    #print("Standard Output: ---------------- ")
    #print(stdout.decode('utf-8'))

    #print("Standard Error: +++++++++++++++++")
    #print(stderr.decode('utf-8'))
    # returns b64 encoded plaintext
    try:
        result_b64 = proc.communicate()[0].decode()
    except Exception as e:
        print(f"Error calling KMS cli: {e}")
    plaintext_b64 = result_b64.split(":")[1].strip()
    return base64.standard_b64decode(plaintext_b64).decode()

def main():
    parser = argparse.ArgumentParser(prog='vsock-sample')
    parser.add_argument("--version", action="version",help="Prints version information.",version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")

    server_parser = subparsers.add_parser("server", description="Server",help="Listen on a given port.")
    server_parser.add_argument("port", type=int, help="The local port to listen on.")
    server_parser.set_defaults(func=server_handler)
    
    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()