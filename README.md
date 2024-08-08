This example shares steps on how to extract sensitive sample data from RDS and process the data in Nitro Enclave(AWS Nitro Enclaves enables customers to create isolated compute environments to further protect and securely process highly sensitive data such as personally identifiable information (PII)). 

**Overview**

**Data flow in this example**
1. Admin ingests KMS encrypted RDS username password into Secrets Manager - This is an independent step to be accomplished outside of NitroEnclave build process 
2. Client Application running on the Ec2 machine retrieves the KMS encrypted access credentials (username and password) for RDS from Secrets Manager and sends the encrypted access credentials along with RDS endpoint to Nitro Enclave processing (the requet parameter also includes IMDSv2 metadat paramaters of teh EC2 machine))
3. Server application running on NitroEnclave decrypts the KMS encrypted credentials using kms_enclave_cli (allows access to KMS over vsock channel using vsock proxy) 
    1. Nitro Enclave includes cryptographic attestation of the enclave which is also added to the KMS key policy so that only the enclave can access the KMS.
4. Server Application running inside the NitroEnclave uses the decrypted credentials to connect to the RDS instances (using the traffic forwarder) and retrieves a sample set of TLS encrypted data from RDS for PII / sensitive data detection (this example does not show detection of sensitive data)
5. NitroEnclave then sends the results of the PII data detection for downstream reporting / cataloguing activity
    1. In this example it sends the data back to client instance running on the parent
  
![image](https://github.com/user-attachments/assets/7722cd9a-4c51-413b-9cd7-ab506aa13448)

**Steps to recreate the Environment** - This Example uses Python code samples
1. Setup your Nitro Enclave environment using Amazon Linux 2023
    1. Create a EC2 machine with Nitro Enclave enabled and 50gb of storage (This can be done from console or using Cli command)
2. Create a KMS Key (use console - You can provide your own key material if needed but for this test we will use AWS generated CMK)
    1. Note the ARN of the key for future use
3. Create a MySQL RDS instance (use console to create the DB) 
    1. Note the ARN of the Database (you can optionally enable TLS on RDS database but this example does not use TLS certificate during RDS requests)
    2. Note the username / password provided when creating the RDS instances for future use
    3. Create a table (Sample shown below for test purpose) and insert some values in to the table
        ```
       CREATE TABLE Persons (
                               SSN INT,
                               NAME VARCHAR(255),
                               AGE INT ,
                               ADDRESS VARCHAR (255)
                            );
        INSERT INTO Persons (SSN, NAME, AGE, ADDRESS) VALUES (123456789, 'joey', 25, NULL);
       ```
4. nstall Mysql and other Python packages required for a later time 
    ```
        sudo yum install mysql
        sudo yum install python3-pip
        sudo yum update -y 
        sudo  yum install -y \
            sudo \
            python3 \
            python3-pip \
            gcc \
            gcc-c++ \
            make \
            openssl-devel \
            libffi-devel \
            wget \
            iproute \
            tar \
            && yum clean all
        pip install boto3
        pip install pybase64
        pip install requests
        pip install python_http_client
        pip install mysql-connector-python
    ```
5. Install Docker and Nitro Enclave Cli on the Ec2 machine — https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html
6. Update the Memory allocation for NitroEnclave
      sudo systemctl stop nitro-enclaves-allocator.service
      sudo vi /etc/nitro_enclaves/allocator.yaml
      update the --- memory_mib: 8000 and save the file
      sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
7. Install the sample vsock Hello world application - Connect to ec2 instance - Install git and clone the git repo - 
      git clone https://github.com/aws/aws-nitro-enclaves-samples.git
      cd aws-nitro-enclaves-samples/vsock_sample/py
8. Prepare the Secrets Manager with encrypted RDS Credentials
    1. Encrypt your RDS username and Password using the sample Script  
    2. Create a new Secret Manager using the encrypted username and password provided by the script above - Use AWS console to create a new secret manager entry
    3. Create a new Policy for the Instance Role to be able to access the secret manager
    4. Attach the Policy to the IAM instance role - This allows the Instance profile to access the secrets manager
9. Deploy kmstool-enclave-cli - https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/main/bin/kmstool-enclave-cli
    1. Move the kms_enclave_cli file and libnsm.so file under aws-nitro-enclaves-samples/vsock_sample/py folder for the Dockerfile.server to access them during the build process
    2. This tool allows Enclave to connect to KMS for decryption of RDS credentials
10. Install the traffic forwarder to forward request from inside Enclave to RDS to query the data - https://github.com/aws-samples/aws-nitro-enclaves-workshop/blob/8e48f98f6923aff725f37ca7099b16da86251aca/resources/code/my-first-enclave/secure-local-channel/traffic_forwarder.py
    1. Copy the forwarder code and paste it in a file under aws-nitro-enclaves-samples/vsock_sample/py folder - retain the name of the file as traffic_forwarder.py 
    2. Update the Dockerfile and run.sh as captured in steps below
11. Update the client.py and server.py code 
12. Install and build the vsock Proxy - https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md
    1. Update the /etc/nitro_enclaves/vsock-proxy.yaml file and make the following entry at the top of the file (follow the indentation pattern as it is set for other entires)
        1. -- {address: <RDS Endpoint ARN>, port: 3306}
    2. Start the 2 vsock proxies proxies in background as follows
        1. vsock-proxy 8000 mstestdb.c23cswqvzlga.us-east-1.rds.amazonaws.com 3306 &
        2. vsock-proxy 7000 kms.us-east-1.amazonaws.com 443 &
13. Update the Dockerfile.server 
14. Update the run.sh script 
15. Build the enclave - Build the Docker image, build the enclave image file, build the enclave, start the Enclave and connect to the console - Note to run the enclave in production mode remove the —debug-mode —attach-console parameter
        nitro-cli terminate-enclave —all
        docker rmi vsock-sample-server:latest
        rm vsock_sample_server.eif
        docker build -t vsock-sample-server -f Dockerfile.server .
        nitro-cli build-enclave —docker-uri vsock-sample-server —output-file vsock_sample_server.eif
        nitro-cli run-enclave —eif-path vsock_sample_server.eif —cpu-count 2 —memory 6000
    The output of this build command should show the following block
       ```
       [
              {
                "EnclaveName": "vsock_sample_server",
                "EnclaveID": "i-0a18f010f7a97308e-enc1912819d422fe7a",
                "ProcessID": 742180,
                "EnclaveCID": 16,
                "NumberOfCPUs": 2,
                "CPUIDs": [
                  1,
                  9
                ],
                "MemoryMiB": 6144,
                "State": "RUNNING",
                "Flags": "NONE",
                "Measurements": {
                  "HashAlgorithm": "Sha384 { ... }",
                  "PCR0": "c3460af5a442e56c24010c2566463369bc40c901028d8b027dbc29947d28df0b1230ef5073c90863b8c2ed062aec7957",
                  "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
                  "PCR2": "344b4ec003898169272c107f730b9d7baeb353d5592da049ebae9d63c9bda8ceb3b18d1d10767b472409c346112443ee"
                }
              }
        ]
       ```
16. Send a request to the server application from Client - In a separate terminal window go to the same folder and execute the following command (enclave cid is a 2 digit number seen visible after executing the enclave describe command)
        cd aws-nitro-enclaves-samples/vsock_sample/py
        python3 client.py client $ENCLAVECID 5000 --------- ENCLAVECID is the 2 digits id shown above in step 15 
17. Observe the output - The console on the step 15 should show the values extracted from RDS instance and the same RDS extracted values should be visible on client terminal 
18. Update the KMS key Policy with Instance role and PCR0 value of the Enclave, this will lock down the access to KMS key only to Enclave (Note the enclave has to be started in production mode for this option to work)
    ```
    {
            "Version": "2012-10-17",
            "Id": "key-default-1",
            "Statement": [
                {
                    "Sid": "Enable decrypt from enclave",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::xxxxxx:role/EC2InstanceROle"
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIgnoreCase": {
                            "kms:RecipientAttestation:ImageSha384": "<add the PCR0 value of the Enclave from the build aboe>"
                        }
                    }
                },
                {
                    "Sid": "Enable encrypt from instance",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::xxxxxxx:role/EC2InstanceROle"
                    },
                    "Action": "kms:Encrypt",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow access for Key Administrators",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::xxxxxxx:role/Admin"
                    },
                    "Action": [
                        "kms:Create*",
                        "kms:Describe*",
                        "kms:Enable*",
                        "kms:List*",
                        "kms:Put*",
                        "kms:Update*",
                        "kms:Revoke*",
                        "kms:Disable*",
                        "kms:Get*",
                        "kms:Delete*",
                        "kms:TagResource",
                        "kms:UntagResource",
                        "kms:ScheduleKeyDeletion",
                        "kms:CancelKeyDeletion",
                        "kms:RotateKeyOnDemand"
                    ],
                    "Resource": "*"
                }
            ]
        }
    ```
19. Clean the environment
    1. Delete the Secrets Manager instance
    2. Delete the KMS key
    3. Terminate the RDS instance and
    4. Terminate the Ec2 instance
