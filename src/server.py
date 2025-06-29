# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0
import argparse
import socket
import sys
import json
import subprocess
import mysql.connector
import psycopg2
from psycopg2 import sql, Error
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
                print('data from Client:', data)
                #parse the json data sent frm parent
                try:
                    data_json = json.loads(data)
                    user_enc = data_json["user"]
                    pass_enc = data_json["pass"]
                    credential = data_json["credential"]
                    dbtype= data_json["dbtype"]
                    dbname= data_json["name"]
                    host= data_json["host"]
                    port= data_json["dbprt"]
                    try:
                        decrtpeduser = kms_call(credential, user_enc)
                        decrtpedpass = kms_call(credential, pass_enc)
                        print("decrtpeduser ---- ",decrtpeduser)
                        print("decrtpedpass ---- ",decrtpedpass)
                    except Exception as e:
                        msg = "exception happened calling kms binary: {}".format(e)
                        print(msg)
                    #user=decrtpeduser,
                    #password=decrtpedpass,

                    if dbtype == "mysql":
                        msrow = mysql_handler(host,port,dbname,decrtpeduser,decrtpedpass)
                        from_client.send(str(msrow).encode())
                    if dbtype == "posgres":
                        pgrow = postgres_handler(host,port,dbname,decrtpeduser,decrtpedpass)
                        from_client.send(str(pgrow).encode())
                    
                except json.JSONDecodeError as e:
                    print(f"Failed to parse JSON: {e}")

                from_client.close()
                print("Client call closed")

            except Exception as ex:
                print(ex)

def postgres_handler(host,port,dbname,user,password):
    print("----@@###### ----In Server side before the call to 1st postgres DB")
    # Database connection parameters
    DB_HOST = host        
    DB_PORT = port                  
    DB_NAME = dbname            
    DB_USER = user          
    DB_PASSWORD = password       
    try:
        # Establishing the connection
        connection = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        #print("Connection to PostgreSQL DB successful")

        # Creating a cursor to execute SQL queries
        cursor = connection.cursor()

        # Example query: Fetching PostgreSQL version
        cursor.execute("SELECT * from Persons;")
        pgrow = cursor.fetchall()
        print("Data From Postgres:", pgrow)
        return pgrow

        # Close the cursor and connection
        #cursor.close()
        #connection.close()
        #print("PostgreSQL connection closed")
    except Error as e:
        print("Error connecting to PostgreSQL:", e)


def mysql_handler(host,port,dbname,user,password):
    print("----@@###### ----In Server side before the call to Mysql DB")
    # Database connection parameters
    DB_HOST = host        
    DB_PORT = port                  
    DB_NAME = dbname            
    DB_USER = user          
    DB_PASSWORD = password 
    print('Here 11111111111',DB_HOST,DB_PORT, DB_NAME, user, password)
    try:
        # Connect to the database
        mysqlcnx = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            ssl_ca='/us-east-1-bundle.pem'    
        )
        # Execute a query
        print('Here 22222222222333333')
        cur = mysqlcnx.cursor()
        print('Here 222222222')
        query = "SELECT * FROM Persons"
        cur.execute(query)
        print('Here 3333333333')
        ms2row = cur.fetchall()
        print('Data from secomd MySql Instance: ',ms2row)
        return ms2row
    # Send back the response                 
        #from_client.send(str(row).encode())
        #from_client.close()
        #print("Client call closed")
    except Error as e:
        print("Error connecting to MySQl:", e)


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
