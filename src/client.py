# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

#!/usr/local/bin/env python3
import argparse
import socket
import sys
import boto3
import json
import requests
import mysql.connector

# Specify your AWS region
aws_region = 'us-east-1'  # Replace with your region

# To call the client, you have to pass: CID of the enclave, Port for remote server, 
# and Query string that will be processed in the Nitro Enclave. For Example:
# $ python3 client.py client 19 5005 "us-east-1"
class VsockStream:
    # Client
    def __init__(self, conn_timeout=30):
        self.conn_timeout = conn_timeout

    def connect(self, endpoint):
        # Connect to the remote endpoint with CID and PORT specified.
        try:
            self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            self.sock.settimeout(self.conn_timeout)
            self.sock.connect(endpoint)
        except ConnectionResetError as e:
            print("Caught error ", str(e.strerror)," ",str(e.errno))

    def is_connected(self):
        try:
            # Attempt to send an empty byte to check connection
            self.sock.send(b'')
            return True
        except (socket.error, BrokenPipeError):
            return False

    def send_data(self, data, endpoint):
        try:
            # Print socket details for debugging
            print(str(self.sock))
            
            # Ensure the socket is connected before sending
            if not self.is_connected():  # Implement an `is_connected` method
                print("Socket is not connected. Reconnecting...")
                self.connect(endpoint)  # Ensure `connect` method handles reconnections
            
            # Send data
            self.sock.sendall(data)
            print("Data Sent:", data)

            # Receive response from server
            resp = self.sock.recv(1024).decode()
            print('Received from server:', resp)
            
            return resp  # Return response for further processing if needed

        except (BrokenPipeError, ConnectionResetError) as e:
            print(f"Connection error: {e}. Reconnecting...")
            self.connect(endpoint)  # Attempt to reconnect
            return self.send_data(data,endpoint)  # Retry sending data after reconnecting

        except Exception as e:
            print(f"Error in send_data: {e}")
            return None  # Return None or handle as needed

        finally:
            # Optionally, close the socket after each operation if desired
            # Uncomment the following line if your use case requires it
            self.sock.close()
            pass



def get_aws_session_token():
    # URL for instance metadata
    # Base URL for instance metadata
    metadata_url = 'http://169.254.169.254/latest/meta-data/'

    # Fetch the token required for IMDSv2
    token_url = 'http://169.254.169.254/latest/api/token'
    headers = {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}

    token_response = requests.put(token_url, headers=headers)
    if token_response.status_code == 200:
        token = token_response.text
    else:
        raise Exception(f"Failed to retrieve IMDSv2 token: {token_response.status_code}, {token_response.text}")

    # Headers with the token for IMDSv2 requests
    token_headers = {'X-aws-ec2-metadata-token': token}

    # Retrieve instance metadata keys
    response = requests.get(metadata_url, headers=token_headers)
    if response.status_code == 200:
        metadata_keys = response.text.split('\n')
        #print("Instance Metadata Keys:", metadata_keys)
    else:
        raise Exception(f"Failed to retrieve metadata keys: {response.status_code}, {response.text}")

    # Retrieve the IAM role name
    iam_role_name_url = metadata_url + 'iam/security-credentials/'
    iam_role_name_response = requests.get(iam_role_name_url, headers=token_headers)
    if iam_role_name_response.status_code == 200:
        iam_role_name = iam_role_name_response.text.strip()
    else:
        raise Exception(f"Failed to retrieve IAM role name: {iam_role_name_response.status_code}, {iam_role_name_response.text}")

    # Retrieve the IAM role credentials
    iam_credentials_url = metadata_url + 'iam/security-credentials/' + iam_role_name
    iam_credentials_response = requests.get(iam_credentials_url, headers=token_headers)
    if iam_credentials_response.status_code == 200:
        iam_credentials = iam_credentials_response.json()  # Use .json() to directly parse JSON response
        #print("Access Key ID:", iam_credentials['AccessKeyId'])
        #print("Secret Access Key:", iam_credentials['SecretAccessKey'])
        #print("Session Token:", iam_credentials['Token'])
        #print("Expiration:", iam_credentials['Expiration'])
    else:
        raise Exception(f"Failed to retrieve IAM role credentials: {iam_credentials_response.status_code}, {iam_credentials_response.text}")
    return iam_credentials

def client_handler(args):
    # creat socket stream to the Nitro Enclave
    client = VsockStream()
    endpoint = (args.cid, args.port)
    #print("Endpoint Arguments ", str(args.cid), str(args.port))
    client.connect(endpoint)
    #Connect to SourceDb to retrieve the list of DBs to parse
    
    print("Connecting to SourceDb")
    #fetch the SourceDb Database connection paramters from Secrest manager
    src_db_hostep, src_db_hostport = get_sm("sm_for_hostep_and_port_for_srcdb")
    src_db_user, src_db_pass = get_sm("sm_for_srcdb")
    # Database connection parameters
    DB_HOST = src_db_hostep       
    DB_PORT = src_db_hostport                  
    DB_NAME = "sourcedbs"            # change the name of the mysql sourcedb if it is created with a name other than sourcedb
    DB_USER = src_db_user          
    DB_PASSWORD = src_db_pass
    try:
        # Connect to the database
        mysqlcnx = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,   
        )
        # Execute a query
        cur = mysqlcnx.cursor(dictionary=True)
        query = "select * from sourcedb"
        cur.execute(query)
        #sdbrow = cur.fetchall()
        #print('Data from secomd MySql Instance: ',sdbrow)
        payload = {} #Json to send to server

        #iterate the result from sourcedb and parse through each entry to send to NitroEnclase server applictaion for processing
        row = cur.fetchone()
        while row:
            print('Processing Value number - ',row)
            dbname=row['NAME']
            dbtype=row['type']
            dbep=row['endpoint']
            dbprt=row['port']
            vsock_proxy=row['vsock_proxy']
            secrets_mgr_ep=row['scmid']
            encuser, encpassword = get_sm(secrets_mgr_ep) 
            dbregion=row['region']
            #create a json payload to send to server 
            payload = {
                "name": dbname,
                "dbtype": dbtype,
                "host": dbep,
                "dbprt": dbprt,
                "user": encuser,
                "pass": encpassword,
                "dbregion": dbregion,
                "credential": get_aws_session_token()
            }
            # Send the request package with parameters to the server running in enclave
            client.send_data(str.encode(json.dumps(payload)),endpoint)
            row = cur.fetchone()
        #mysqlcnx.close()
    except BrokenPipeError:
        print("Broken pipe error. Re-establishing connection.")
        client.connect()  # Replace with the reconnect logic
    except Exception as e:
        print("Error In CLient Connect to Sourcedbs:", e)

def get_sm(secrets_mgr_ep):
        #Fetch the Secrests Manager values Create a Secrets Manager client
        boclient = boto3.client('secretsmanager', region_name=aws_region)
        try:
            get_secret_value_response = boclient.get_secret_value(SecretId=secrets_mgr_ep)
        except Exception as e:
                print(f"Error retrieving secret: {e}")
        # Parse the secret value
        secret = get_secret_value_response['SecretString']
        secret_dict = json.loads(secret)
        user=secret_dict['username']
        password=secret_dict['password']
        return user, password

def main():
    # Handling of input parameters
    parser = argparse.ArgumentParser(prog='vsock-sample')
    parser.add_argument("--version", action="version", help="Prints version information.", version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")

    client_parser = subparsers.add_parser("client", description="Client",
                                          help="Connect to a given cid and port.")
    client_parser.add_argument("cid", type=int, help="The remote endpoint CID.")
    client_parser.add_argument("port", type=int, help="The remote endpoint port.")
    #client_parser.add_argument("query", type=str, help="Query to send.")

    # Assign handler function
    client_parser.set_defaults(func=client_handler)

    # Argument count validation
    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()