# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

#!/usr/local/bin/env python3
import argparse
import socket
import sys
import boto3
import json
import requests

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


    def send_data(self, data):
        # Send data to the remote endpoint
        #print(str(self.sock))
        # encode data before sending
        self.sock.sendall(data)
        print("Data Sent ", data)
        # receiving responce back
        data =  self.sock.recv(1024).decode()  # receive response
        print('Received from server: ' + data)  # show in terminal
        self.sock.close()

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
    # Send provided query and handle the response
    # Create a Secrets Manager client
    boclient = boto3.client('secretsmanager', region_name=aws_region)
    try:
        # Retrieve the secret
        #print('Get Secret Value:')
        get_secret_value_response = boclient.get_secret_value(SecretId="<Enter the Secret Id here>")
        #print('Get Secret Value:',get_secret_value_response)
    except Exception as e:
        print(f"Error retrieving secret: {e}")

    # Parse the secret value
    secret = get_secret_value_response['SecretString']
    secret_dict = json.loads(secret)
    user=secret_dict['username']
    password=secret_dict['password']
    host="mstestdb.c23cswqvzlga.us-east-1.rds.amazonaws.com"

    #create a json payload to send to server with credentials of the parent
    payload = {}
    # Get EC2 instance metedata
    payload["host"] = host
    payload["user"] = user
    payload["pass"] = password
    # Get EC2 instance metadata
    payload["credential"] = get_aws_session_token()
    #print("Payload Values: --- ",payload)

    # Send AWS credential to the server running in enclave
    client.send_data(str.encode(json.dumps(payload)))
    

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
