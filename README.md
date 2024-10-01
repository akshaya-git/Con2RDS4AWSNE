# Secure Data Processing with AWS Nitro Enclaves

## Overview

This project demonstrates how to securely extract and process sensitive sample data from an RDS instance using AWS Nitro Enclaves. Nitro Enclaves provide isolated compute environments designed for handling highly sensitive data, such as personally identifiable information (PII), with enhanced security measures.

## Data Flow

1. **Admin Setup**: Ingest KMS-encrypted RDS credentials (username and password) into AWS Secrets Manager. This step is performed independently, outside the Nitro Enclave build process.

2. **Client Application**: An EC2 instance retrieves the KMS-encrypted RDS credentials from Secrets Manager and sends them, along with the RDS endpoint and EC2 instance metadata (IMDSv2), to the Nitro Enclave for processing.

3. **Nitro Enclave Decryption**: The Nitro Enclave uses `kms_enclave_cli` to decrypt the KMS-encrypted credentials through a secure vsock channel. The enclave’s cryptographic attestation, included in the KMS key policy, ensures only the enclave can access the key.

4. **Data Retrieval**: Using the decrypted credentials, the Nitro Enclave connects to the RDS instance via a traffic forwarder to retrieve a sample set of TLS-encrypted data for PII/sensitive data detection (note: detection functionality is not included in this example).

5. **Reporting**: The results from the Nitro Enclave are sent back to the EC2 client instance for further reporting or cataloging.
  
![image](https://github.com/user-attachments/assets/7722cd9a-4c51-413b-9cd7-ab506aa13448)

## Steps to Recreate the Environment (Using Python)

1. **Set Up Nitro Enclave Environment**:
     - Create an EC2 instance with Nitro Enclave enabled and 50 GB of storage.

      ```
        aws ec2 run-instances \
        --image-id ami-0b5eea76982371e91 \
        --count 1 \
        --instance-type m5.xlarge \
        --key-name forssh \
        --enclave-options 'Enabled=true' \
        --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":20}}]'
      ```
      
2. **Create KMS Key**:
     - Generate a KMS Customer Managed Key (CMK) and note the ARN for later use.

3. **Create MySQL RDS Instance**:
     - Provision an RDS instance, noting its ARN, username, and password.

4. **Install Required Tools on EC2**:
     - Install MySQl and other Python packages on the Ec2 machine
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
      ```
     - Install Docker and Nitro Enclave CLI. [Installation Guide](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html).

5. **Configure Memory Allocation for Nitro Enclave**:
   ```bash
      sudo systemctl stop nitro-enclaves-allocator.service
      sudo vi /etc/nitro_enclaves/allocator.yaml
      update the --- memory_mib: 8000 and save the file
      sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
      ```

6. **Install Sample vsock Hello World Application**: 
      ```
      git clone https://github.com/aws/aws-nitro-enclaves-samples.git
      cd aws-nitro-enclaves-samples/vsock_sample/py
      ```
7. **Prepare the Secrets Manager**
    1. Encrypt your RDS username and Password using the sample Script  (Under src folder)
    2. Create a new Secret Manager using the encrypted username and password provided by the script - Use AWS console to create a new secret manager entry
    3. Create a new Policy for the Instance Role to be able to access the secret manager
      ```
      {
            "Version": "2012-10-17",
            "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "arn:aws:secretsmanager:us-east-1:xxxxxxxx:secret:xxxxxxxxxx"
            }
            ]
      }
      ```
    4. Attach the Policy to the IAM instance role - This allows the Instance profile to access the secrets manager
       
8.  **Donwload and Package the RDS CA certificate Bundle**
    1. Click on the link - https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem to download the ca cert bundle for us-east-1 region.
    2. If there is a need for another region then download the respective bundle form - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html  
    3. Place the downloaded bundle under _aws-nitro-enclaves-samples/vsock_sample/py_ folder
    4. To Download the rds ca cert bundle directly to Ec2 machine use the curl command
       ```
       curl https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem
       Copy the content from curl command and paste it in a file with same name - us-east-1-bundle.pem
       ```

9.  **Deploy kmstool-enclave-cli** 
    1. Follow the instructions in the link here - https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/main/bin/kmstool-enclave-cli 
    2. Move the kms_enclave_cli file and libnsm.so file under aws-nitro-enclaves-samples/vsock_sample/py folder for the Dockerfile.server to access them during the build process
    3. This tool allows Enclave to connect to KMS for decryption of RDS credentials
       
10. **Install the traffic forwarder:** to forward request from inside Enclave to RDS to query the data 
    1. Copy the forwarder code from https://github.com/aws-samples/aws-nitro-enclaves-workshop/blob/8e48f98f6923aff725f37ca7099b16da86251aca/resources/code/my-first-enclave/secure-local-channel/traffic_forwarder.py and paste it in a file under aws-nitro-enclaves-samples/vsock_sample/py folder - retain the name of the file as traffic_forwarder.py
       
11. **Update Client and Server Code:**
    1. Modify client.py and server.py in the src folder as per the requirements.
       
12. **Install / build and Start the vsock Proxy:**
    1. Follow the instructions here to install and build the vsock proxy - https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md
    2. Update the /etc/nitro_enclaves/vsock-proxy.yaml file with
       ```
       -- {address: <RDS Endpoint ARN>, port: 3306}
       ```
    3. Start the 2 vsock proxies proxies in background as follows
       ```
       vsock-proxy 8000 mstestdb.c23cswqvzlga.us-east-1.rds.amazonaws.com 3306 &
       vsock-proxy 7000 kms.us-east-1.amazonaws.com 443 &
       ```
13. **Update Dockerfile.server:**
    1. Modify the Dockerfile.server located in the src folder.
       
14. **Update run.sh Script:**
    1. Modify the run.sh script located in the src folder.
       
15. **Build the enclave:**
    1. Build the Docker image, enclave image file and run the enclave.
    ```
        docker build -t vsock-sample-server -f Dockerfile.server .
        nitro-cli build-enclave —docker-uri vsock-sample-server —output-file vsock_sample_server.eif
        nitro-cli run-enclave —eif-path vsock_sample_server.eif —cpu-count 2 —memory 6000
    ```
    The output of this build command should look as follows
       ```[
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
       
16. **Update the KMS key Policy:**
    1. Update the KMS key policy to restrict access based on the instance role and PCR0 value of the Enclave (ensure the enclave is started in production mode for this option to work):
    ```{
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
    
17. **Send a request to the server application from Client:**
    1. In a separate terminal window go to the same folder and execute the following command (enclave cid is a 2 digit number seen visible after executing the enclave describe command)
```
    cd aws-nitro-enclaves-samples/vsock_sample/py
    python3 client.py client $ENCLAVECID 5000 --------- Replace ENCLAVECID with the 2 digit EnclaveCID value from previous step
```

17. **Observe the output:**
    1. The console should display the values extracted from the RDS instance. In a real-world scenario, it will send a confirmation if sensitive data is detected.

18. **Clean the environment:**
    1. Delete the Secrets Manager instance
    2. Delete the KMS key
    3. Terminate the RDS instance and
    4. Terminate the Ec2 instance
