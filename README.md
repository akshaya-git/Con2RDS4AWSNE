# Use AWS NitroEnclave to securely Query Sample data from RDS (Do not use this in production until it is tried and tested on Dev and QA)

## Overview (Do not use this in production until it is tried and tested on Dev and QA)

Large organizations manage multiple databases across various lines of business, each potentially storing sensitive data such as Personally Identifiable Information (PII). Compliance teams often require organizations to identify and catalog databases containing sensitive data. Additionally, legacy and modern applications may need to be analyzed for such data without relying solely on developer-provided documentation. However, accessing this data outside the application introduces security risks, as traditional extraction methods often expose data to administrators, operators, or attackers in the event of a memory dump or unauthorized access. There needs to be a secure and contained environment to query the databases while maintaining strong security controls where a sample subset of sensitive data can be extracted without operator access even in scenarios where the underlying system’s memory is compromised. This solution leverage AWS NitroEnclave to query a sample subset of data which can then be parsed for a presence of sensitive data 

**Note** - This document does not focus on detecting the presence of sensitive data. Instead, it provides a secure method for connecting to existing AWS RDS databases from inside a Nitro Enclave to extract a subset of data without exposing it to unauthorized users.

## About this Guide and AWS NitroEnclaves

This guide outlines a process to securely connect to AWS-managed databases (RDS) and extract a subset of sensitive data using AWS Nitro Enclaves. AWS Nitro Enclaves provide isolated compute environments designed to securely process highly sensitive data. By [leveraging Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) organizations can ensure that:

* Sensitive data remains inaccessible to operators and even system administrators with root / admin access.
* Data extraction processes occur in a trusted execution environment (TEE), preventing unauthorized access—even if the underlying EC2 instance is compromised.
* The AWS Key Management Service (KMS) attestation feature is used to restrict access to decryption keys, ensuring that only verified Nitro Enclaves can access encrypted RDS connection credentials stored in AWS Secrets Manager.

## Solution Architecture
![Image (8)](https://github.com/user-attachments/assets/d0c40028-e7b4-459f-933d-203b98d66f47)

# Services used in this example 

1. **Databases**
    1. Source Database (RDS mysql used for this teast) - The Source Database stores relevant information of the all the target databases to scan for sensitive data and 
    2. Target Database (RDS mysql and postgres used for this test) - The target databases are the various databases where there is data that needs to be queried. 
2. **KMS** - A customer managed key to encrypt the RDS database username and password
5. **Secrets Manager** 
    1. Admin ingests KMS encrypted (i.e. encrypted before storing in secrets manager) username and password of every target database into Secrets Manager. Note that the default encryption of secrets manager is **NOT** used instead a KMS is key created specifically to encrypt the credentials before ingesting the credentials in secrets manager. 
6. **IAM**
    1. The Instance profile (IAM role attached to the Amazon EC2 instance hosting the Nitro Enclave) is given explicit permission to access the secrets created in secrets manager
7. **Ec2 and NitroEnlave** 
    1. Enclaves are fully isolated virtual machines, hardened, and highly constrained inside a an Ec2 machine. They have no persistent storage, no interactive access, and no external networking. Communication between your instance and your enclave is done using a secure local channel. Even a root user or an admin user on the instance will not be able to access or SSH into the enclave. Nitro Enclaves use the proven isolation of the Nitro Hypervisor to further isolate the CPU and memory of the enclave from users, applications, and libraries on the parent instance. These features help isolate the enclave and your software, and significantly reduce the attack surface area.
8. **Vsock proxies for Secure communication**
    1. A vsock proxy runs on the parent instance and securely forwards traffic between the enclave and external TCP endpoints from an enclave to a TCP endpoint. It can be run independently or as a service. - https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md 


## Data Flow

1. **Client Application on Parent Ec2 Machine -**
    1. Client Application running on the Ec2 machine queries the source database and retrieves the list of target databases that needs to be queried for sample data
    2. It then retrieves the encrypted username and password of the corresponding target database from the secrets manager
    3. It then sends a request (over vsock channel) to server application inside the NitroEnclave for processing
    4. The request from client Application contains the encrypted access credentials of the database, IMSDV2 acces key and token of the Ec2 machine along with RDS endpoint of the target database

2. **Server Application inside Nitro Enclave -**
    1. Server application running inside NitroEnclave receives the request to connect and query the target database with its endpoint and encrypted username password 
    2. It first decrypts the username and password using KMS cli (kms_enclave_cli) packaged with the enclave when it was built
        1. Access to KMS for decrypt request from Server application is restricted only to NitroEnclave (exmaple shown below in the documentation)
            1. When NitroEnclave is created a 384 bit / 96 bytes long cryptographic attestation key containing the Platform Configuration Register (PCR) hash value is generated. PCR refers to a security feature within a Trusted Platform Module (TPM) that stores a cryptographic hash representing the current system configuration, essentially acting as a digital fingerprint of the system state at a specific point in time. 
            2. This PCR Hash cryptographic value is added as a condition to the AWS KMS key definition for attestation that restricts the access to decrypt function of the KMS key to only the corresponding NitroEnclave.
            3. When the Server application communicates with AWS KMS services using the kms_enclave_cli Nitro SDK API request packages the PCR hash value for access validation. If the PCR hash value does not match the value specified in KMS condition for decrypt then the decrypt call will fail.
    3. Once the database credentials are decrypted it then connects to the target RDS Database using traffic forwarder of respective database and queries for a sample seubset of data from the database
    4. All communication is encrypted and secure over a vsock channel and proxies configured specifically for communication with the target database

---

## Steps to recreate the Environment - 

## Setup Ec2 environment
1. Create a EC2 machine with Nitro Enclave enabled and at least 20 gb of storage This can be done from console or Cli command below. If using the console remember to enable the enclave support for the instance
  ```
      aws ec2 run-instances \
        --image-id ami-0b5eea76982371e91 \
        --count 1 \
        --instance-type m5.xlarge \
        --key-name forssh \
        --enclave-options 'Enabled=true' \
        --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":20}}]'
```
2. Connect to the Ec2 instances using ssh or AWS Session Manager  and Install following packages 
   ```
        sudo yum install mysql
        sudo yum install python3-pip
        sudo yum update -y 
        sudo yum install -y \
            aws-cli \
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
            gzip \
            bzip2-devel \
            openssh-server \
            unzip \
            sed \
            jq \
            postgresql15 \
            postgresql-devel \
            && yum clean all
        pip3 install boto3
        pip3 install pybase64
        pip3 install requests
        pip3 install python_http_client    
        pip3 install psycopg2-binary

---
   
# AWS RDS Sensitive Data Scanning with Nitro Enclaves

## Create a KMS Key

1. Using AWS console, create a new KMS key (customer managed). You can provide your own key material if needed, but for this test we will use AWS generated CMK.
2. Note the ARN of the key to use for encrypting the username and password of the databases.

---

## Prepare / Create the Source and Target Databases in RDS

### Source Database

- Create a Source Database in RDS (for this test we will use RDS MySQL) that will store relevant information of all the target databases to query for data.
- Once the Source database is created, connect to the source database and create a table that will store relevant target database information as follows:

    ```
    CREATE TABLE sourcedb (
       NAME VARCHAR(255),
       type VARCHAR(255),
       endpoint VARCHAR(255),
       port INT,
       vsock_proxy INT,
       scmid VARCHAR(255),
       region VARCHAR(255)
    );
    ```

### Target Database

- Use existing RDS databases or create a MySQL and Postgres database each with some sample data that will be queried from inside the Nitro Enclave. The target databases are the databases where there is data that needs to be scanned for sensitive information.
    1. Note the username and password of the target database.
    2. Using the KMS key created above, encrypt the username and password of each database. You can create a custom script to do this (a sample python script provided under src folder) or just use the AWS CLI to encrypt the username and password:

        ```
        aws kms encrypt \
          --key-id YOUR_KMS_KEY_ID \
          --plaintext "username or password" \
          --output text \
          --query CiphertextBlob
        ```

    3. Using the encrypted username and password, create a Secrets Manager identity for each target database and note the Secrets Manager ID.
        1. Grant permission to the EC2 instance Role (for the EC2 instances created above) to access the Secrets Manager.
        2. Create a new IAM Policy for the Instance Role.
        3. Attach the ARNs of all Secrets created for Target Database.
        4. Once the policy is created, the JSON for the policy will look as follows (`xxxxx` will be the unique value system generated for the secret):

            ```
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": [
                            "arn:aws:secretsmanager:<region>:<account-id>:secret:mstestdbsec_enc-xxxxx",
                            "arn:aws:secretsmanager:<region>:<account-id>:secret:sm_for_pgtestdb-xxxxx",
                            "arn:aws:secretsmanager:<region>:<account-id>:secret:sm_for_hostep_and_port_for_srcdb-xxxxx",
                            "arn:aws:secretsmanager:<region>:<account-id>:secret:sm_for_srcdb-xxxxx"
                        ]
                    }
                ]
            }
            ```

        5. Attach the Policy to the IAM instance role. This allows the Instance profile to access the Secrets Manager.

    4. Note the port on which the database runs.
    5. Note the endpoint ARN (Amazon Resource Name, a unique identifier for each resource in AWS) of the database.
    6. Note the database name and the tables to query.
    7. **Security Note:**
        1. Enable [encryption of data at rest for Amazon RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html) for all the target databases.
        2. Use [SSL/TLS to encrypt connections to RDS DB instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html) for secure communication with target databases.
    10. **Populate the Source and Target Database:**
        1. Once the Target database and source database are created, populate the source database with relevant target database parameters, if the target database is a new database then create a table and enter some sample data to query using this example. Here is a sample of what the source database will look like after it is populated:

            ![Sample Source DB](https://github.com/user-attachments/assets/2f796c41-0f98-41da-b6f6-3eb2f8ee554a)

---

## Setup the EC2 Instance with Nitro Enclave

1. **Install Docker and Nitro Enclave CLI**  
   [AWS Nitro Enclave CLI Installation Guide](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html)

    ```
    sudo amazon-linux-extras install docker
    sudo systemctl start docker
    sudo systemctl enable docker
    sudo usermod -a -G docker ec2-user
    sudo amazon-linux-extras enable aws-nitro-enclaves-cli
    sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
    nitro-cli --version
    ```

2. **Update the Memory Allocation**

    ```
    sudo systemctl stop nitro-enclaves-allocator.service
    sudo vi /etc/nitro_enclaves/allocator.yaml
    # update the memory_mib: 8000 and save the file
    sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
    ```

3. **Install the sample vsock Hello World application**  
   Connect to EC2 instance, install git (if needed) and clone the git repo:

    ```
    git clone https://github.com/aws/aws-nitro-enclaves-samples.git
    cd aws-nitro-enclaves-samples/vsock_sample/py
    ```

4. **Build and Deploy kmstool-enclave-cli**  
   [kmstool-enclave-cli](https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/main/bin/kmstool-enclave-cli)
    - Move the `kmstool_enclave_cli` file and `libnsm.so` file under `aws-nitro-enclaves-samples/vsock_sample/py` folder for the `Dockerfile.server` to access them during the build process.
    - This tool allows Enclave to connect to KMS for decryption of RDS credentials.

5. **Download build and create the vsock Proxy for KMS and each Target Database**  
   [vsock proxy README](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md)

    ```
    git clone https://github.com/aws/aws-nitro-enclaves-cli.git
    cd aws-nitro-enclaves-cli
    make vsock-proxy
    ```

    - Update the `/etc/nitro_enclaves/vsock-proxy.yaml` file and make the following entry at the top of the file (follow the indentation pattern as it is set for other entries):

        ```
        - {address: <RDS Target MySql Endpoint ARN>, port: 3306}
        - {address: <RDS Target Postgres Endpoint ARN>, port: 5432}
        - {address: <kms.us-east-1.amazonaws.com>, port: 443} //update the KMS ARN if other region is used
        ```

6. **Start the vsock proxies in background as follows:**

    ```
    sudo vsock-proxy 8000 <RDS Target MySql endpoint ARN> 3306 &
    sudo vsock-proxy 8002 <RDS Target Postgres endpoint ARN> 5432 &
    sudo vsock-proxy 7000 kms.us-east-1.amazonaws.com 443 &
    ```

7. **Deploy the traffic forwarder**  
   Forward requests from inside Enclave to RDS to query the data:  
   [traffic_forwarder.py](https://github.com/aws-samples/aws-nitro-enclaves-workshop/blob/8e48f98f6923aff725f37ca7099b16da86251aca/resources/code/my-first-enclave/secure-local-channel/traffic_forwarder.py)

    - Copy the forwarder code and paste it in a file under `aws-nitro-enclaves-samples/vsock_sample/py` folder - retain the name of the file as `traffic_forwarder.py`.

8. **Deploy SSL/TLS for RDS**  
   If SSL/TLS is enabled, then download the RDS CA certificate bundle to implement SSL/TLS for encrypted network communication:
    1. Download the CA bundle for us-east-1 region:  
       [us-east-1-bundle.pem](https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem)  
       For other regions, see [RDS SSL/TLS documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html).
    2. Place the downloaded bundle under `aws-nitro-enclaves-samples/vsock_sample/py` folder.
    3. To download the RDS CA cert bundle directly to EC2 machine, use the `curl` command to the URL above and then copy paste the content to the file of same name as the bundle.
    4. Note the Dockerfile.server under src folder to find the reference to this certificate bundle to be packaged during NitroEnclave build

9. **Download and update the sample code from under src folder**  
   (Modify the sample code as needed to fit your environment)
    - Client application python code: `client.py`
    - Server application python code: `server.py`
    - Sample `Dockerfile.server`
    - Sample `run.sh` script

10. **Build the enclave**  
    Build the Docker image, build the enclave image file, build the enclave, start the Enclave and connect to the console.  
    **Note:** To run the enclave in debug mode, add the `--debug-mode --attach-console` parameter to run-elcave command though that will bypass the KMS PCR has condition.

    ```
    nitro-cli terminate-enclave --all # (This command will fail for the first run as teh enclave does not exist)
    docker rmi vsock-sample-server:latest
    rm vsock_sample_server.eif
    docker build -t vsock-sample-server -f Dockerfile.server .
    nitro-cli build-enclave --docker-uri vsock-sample-server --output-file vsock_sample_server.eif
    nitro-cli run-enclave --eif-path vsock_sample_server.eif --cpu-count 2 --memory 6000
    sudo nitro-cli describe-enclaves
    ```

11. **Update the KMS key Policy with Instance admin role and PCR0 value of the Enclave**  
    This will lock down the access to KMS key only to Enclave (Note: the enclave has to be started in production mode for this option to work).
    - Add the following roles as Key administrators:
        - `EpoxyChronicleInstanceRole`
        - `Admin`

    ```
    {
        "Version": "2012-10-17",
        "Id": "key-default-1",
        "Statement": [
            {
                "Sid": "Enable decrypt from enclave",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::xxxxxx:role/EpoxyChronicleInstanceRole"
                },
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:ImageSha384": "a00e6d309b913ae0d5baf1e9612f0bf8711d7cbeb502b7a34dcc3706a607c0e2d061ced7d8ccef7dd67d2edb529ba4c6"
                    }
                }
            },
            {
                "Sid": "Enable encrypt from instance",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::xxxxxxx:role/EpoxyChronicleInstanceRole"
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

12. **Send a request to the server application from Client**  
    In a separate terminal window, go to the same folder and execute the following command (enclave CID is a 2 digit number visible after executing the enclave describe command):

    ```
    cd aws-nitro-enclaves-samples/vsock_sample/py
    python3 client.py client $ENCLAVE_CID 5000
    ```

    - Observe the output. The console on step 12 should show the values extracted from the RDS instance.
