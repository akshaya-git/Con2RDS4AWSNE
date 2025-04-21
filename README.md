# Secure Data Processing with AWS Nitro Enclaves

## Overview

Large organizations manage multiple databases across various lines of business, each potentially storing sensitive data such as Personally Identifiable Information (PII). A frequent requirement from compliance teams is to identify and catalog databases that hold sensitive information while ensuring secure data extraction.
In many cases, organizations already have scripts to determine whether data is sensitive. However, accessing this data outside the application introduces security risks, as traditional extraction methods often expose data to administrators, operators, or attackers in the event of a memory dump or unauthorized access.
To address this, there is a need for a secure and contained environment where a sample subset of sensitive data can be extracted without operator access, even in scenarios where the underlying system’s memory is compromised. Additionally, applications developed over the years must be parsed to detect the presence of such sensitive data—without solely relying on application developers to provide reports. Instead, a secure backend probing mechanism is required to directly query the database while maintaining strong security controls.

**Note** - This document does not detect the presence of sensitive data but instead focuses on a secure way to connect to existing RDS databases from inside a NitroEnclave and select a subset of data from the database.

## Solution Overview

This guide outlines a process to securely connect to AWS-managed databases (RDS) and extract a subset of sensitive data using AWS Nitro Enclaves. AWS Nitro Enclaves provide isolated compute environments designed to securely process highly sensitive data. By leveraging Nitro Enclaves, organizations can ensure that:

* Sensitive data remains inaccessible to operators and even system administrators with root / admin access.
* Data extraction processes occur in a trusted execution environment (TEE), preventing unauthorized access—even if the underlying EC2 instance is compromised.
* The AWS Key Management Service (KMS) attestation feature is used to restrict access to decryption keys, ensuring that only verified Nitro Enclaves can access encrypted RDS connection credentials stored in AWS Secrets Manager.


## Data Flow

1. **Secrets Manager**
    1. Admin ingests KMS encrypted (i.e. encrypted before storing in secrets manager) RDS username password into Secrets Manager for each of the target database - This is an independent step to be accomplished outside of NitroEnclave build process (Sample script provided below)
    2. Admin also creates 2 other secrets in secrests manager for Source Database (**sourcedbs**) using default secrets manager / KMS encryption (this will secure database connection parameters as well as minimize hardcoding database parameters in clear text in the code)
        1. First entry is to store encrypted username password for the source database and
        2. Second entry is to store the encrypted host endpoint and port of the sourced batabase 

2. **IAM**
    1. The Instance profile (Ec2 instance where Nitro Enclave is built) is given explicit permission to access the secrets created in step 1 above

3. **Ec2 -Client Application** Once deployed the client Application running on the Ec2 machine retrieves the source database parameters and the KMS encrypted access credentials (username and password) for RDS target databases from Secrets Manager and iterates through every entry of the source database and then
    1. Sends a request over vsock channel that contains the access credentials along with RDS endpoint to the server application listening on port 5000 inside the Nitro Enclave for Metadata and sample data processing

4. **Nitro Enclave - Server application** running inside NitroEnclave decrypts the KMS encrypted credential received from client application using kms_enclave_cli (allows access to KMS over vsock channel and using vsock proxy)  
    1. Nitro Enclave includes cryptographic attestation of the enclave which is also added to the KMS key policy so that only the enclave can access the KMS.
    2. Nitro SDK API request packages the PCR hash value generated when the enclave was created in request to KMS when attempting to decrypt the username and poassword. If the PCR hash value does not match the value specified in KMS condition for decrypt then the decrypt call will fail.
    3. Server Application running inside the NitroEnclave then uses the decrypted credentials to connect to the RDS instances (using the traffic forwarder) and retrieves a sample set of TLS encrypted data subset from RDS (Mysql or Postgres) for PII / sensitive data detection 
    4. NitroEnclave then sends the results of the PII data detection for downstream reporting / cataloguing activity
    5. In this example it sends the data back to client instance running on the parent instance for example purpose

5. **Reporting**: The results from the Nitro Enclave are sent back to the EC2 client instance for further reporting / cataloging.
  
![Image (8)](https://github.com/user-attachments/assets/d0c40028-e7b4-459f-933d-203b98d66f47)

## Setup Ec2 environment

1. Create a EC2 machine with Nitro Enclave enabled and at least 20 gb of storage This can be done from console (preferable) or Cli command below (create the ec2 machine from console or from Cli using the command below). If using the console remember to enable the enclave support for the instance
  ```
      aws ec2 run-instances \
        --image-id ami-0b5eea76982371e91 \
        --count 1 \
        --instance-type m5.xlarge \
        --key-name forssh \
        --enclave-options 'Enabled=true' \
        --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":20}}]'
```
2. Connect to the Ec2 instances using ssh and Install following packages. Install Mysql and other Python packages required for a later time 
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
        #pip3 install postgresql-devel

## Create a KMS Key
1. Using AWS console create a new KMS key customer managed - You can provide your own key material if needed but for this test we will use AWS generated CMK)
2. Note the ARN of the key to use for encrypting the username and password of the databases

## Create Source and Target Databases in RDS
1. **Source Database** - The Source Database is a mysql instance that will store relevant information of the all the target databases to scan for sensitive data and 
2. **Target Database** - The target database are the different databases where there is data that needs to be scanned for sensitive information. This test will include 2 target databases one Mysql Instance and second a Postgres instance 
3. First create the Create **target** Databases
    1. Create a RDS MySql database with following settings in Console
        1. Use the free tier 
        2. Note the database identifier that you provide
        3. Select the Self Managed options for Credential Management and provide a Master password (note the username and password)
        4. Select the t3 micro for instance configuration
        5. For storage type leave it to default value of gp2 and 20gb storage
        6. Under connectivity select Connect to an Ec2 compute resource and select the Ec2 instance created above - This will create the security groups required for teh Ec2 instance and database to communicate
        7. Leave rest of the values as default and create the database instance
        8. Note the ARN of the Database and note the Master username and password 
    2. Similarly create another RDS Postgres database using the console - - note the Master username and password for use later
4. Go back to the EC2 ssh terminal and connect to the MySql instance just created 
    1. Connect to RDS mySql instance and create a database —
       ```
            mysql -h <Endpoint of the RDS MySQl DB> -u admin -p 
            mysql - ------ Enter the Password set for the DB during creation
            MySQL [(none)]> Create database <DB name> 
            use <DB name>
       ```
   3. Create a table and ingest encrypted Mock data using the commands below
      ```
             CREATE TABLE Persons (
                 SSN INT,
                 NAME VARCHAR(255),
                 AGE INT ,
                 ADDRESS VARCHAR (255)
              );
            
            INSERT INTO Persons (SSN, NAME, AGE, ADDRESS) VALUES (123456789, 'msjoey', 25, NULL);
      ```
      
    5. Connect to Postgres instance and create a databese —
       ``` 
            psql -host =<ARN of the RDS MySQl DB> --port=5432 -username=<username of the Instance> 
            Password for user postgres: ------ Enter the Password set for the DB during creation 
            postgres[(none)]> Create database <DB name> 
            \c <DB name>
       ```
    6. Create a table and ingest Mock data using the commands below
       ```
           CREATE TABLE Persons (
               SSN INT,
               NAME VARCHAR(255),
               AGE INT ,
               ADDRESS VARCHAR (255)
            );
        
        INSERT INTO Persons (SSN, NAME, AGE, ADDRESS) VALUES (123456789, 'pgjoey', 25, NULL);
       ```
5. Create a parameter group to enforce secure communication with MySql database
    1. Go to Parameter Group under RDS and click on create Parameter Group
    2. Provide the name as require-secure-transport
    3. Under engine type provide MySql Community and for the Parameter Group family provide the MySql version used when creating the MySql instance
    4. Select Db Parameter Group for type and click on Create
    5. Once the parameter group is created click Edit on the parameter group and click on top right corner and search for the require_secure_transport parameter and set the value to 1 
    6. Save Changes
       
6. Go to RDS in Console and click on the MySql Database created in previous step and click on Modify to update the the Db Parameter Group
    1. Scroll down to Additional Configuration and under DB Parameter Group select require-secure-transport value and click on Continue and then select Apply Immediately and then Modify DB Instance
    2. Once the Database is back in Available state reboot the MySql instance to enforce secure communication with the database
    3. Once the instance is rebooted go to next step
       
7. Create a parameter group to enforce secure communication with Postgres database
    1. Go to Parameter Group under RDS and click on create Parameter Group
    2. Provide the name as force-secure-transport
    3. Under engine type select PostgresSQL and for the Parameter Group family provide the PostgresSQL version used when creating the instance
    4. Select Db Parameter Group for type and click on Create
    5. Once the parameter group is created click Edit on the parameter group and click on top right corner and search for the force_ssl parameter and set the value to 1 
    6. Save Changes and now apply the parameter group to the Postgres RDS instance created in previous step
       
8. Go to RDS in Console and click on the Database created in previous step and click on Modify the Db Parameter Group
    1. Scroll down to Additional Configuration and under DB Parameter Group select require-secure-transport value and click on Continue and then select Apply Immediately and then Modify DB Instance
    2. Once the Database is back in Available state restart the Postgres instance to enforce secure communication with the database
    3. Once the instance is rebooted go to next step
       
9. Prepare the Secrets Manager with encrypted RDS Credentials - Do this for every target database
    1. Encrypt your RDS username and Password using the Script provided in the supporting files folder (you can do this on the Ec2 machine created for Nitro Enclave) - update the KMS Key ID, username and password in the script
    2. Using AWS Console create →  Secrets Manager create 2 new secrets using the encrypted username and password provided by the script above. 
        1. Name the one with MySql credentials as mstestdbsec_enc and 
        2. Name the one with PostgresSQL credentials as sm_for_pgtestdb 

10. Create the Source MySQL RDS instance (use console to create the DB) - 
    1. During Source Database creation provide the database identifier as sourcedbs → This will avoid any code change else note the database identifier value provided during creation
    2. Now Connect to the SourceDb
       ```
            mysql -h <ARN of the RDS MySQl DB> -u admin -p 
            mysql - ------ Enter the Password set for the DB during creation
            MySQL> Create database sourcedbs; 
            use sourcedbs;
       ```
    3. Create a sourcedb table and ingest database information
       ```
           CREATE TABLE sourcedb (
               NAME VARCHAR(255),
               type VARCHAR (255),
               endpoint VARCHAR(255),
               port INT,
               vsock_proxy INT,
               scmid VARCHAR(255),
               region VARCHAR(255)
            );
        <replace the relevant values in the insert statement below> - leave other values as is and update them later
        INSERT INTO sourcedb (NAME, TYPE, ENDPOINT, PORT, VSOCK_PROXY,SCMID,REGION) VALUES ('MySQl2', 'mysql', 'mstestdb3.c23cswqvzlga.us-east-1.rds.amazonaws.com', 3306, 8001, 'mstestdbsec_enc', 'us-east-1');
        INSERT INTO sourcedb (NAME, TYPE, ENDPOINT, PORT, VSOCK_PROXY,SCMID,REGION) VALUES ('PgSQl1', 'posgres', 'pgtestdb.c23cswqvzlga.us-east-1.rds.amazonaws.com', 5432, 8002, 'sm_for_pgtestdb', 'us-east-1');
      
11. Create 2 new secrets for sourcedb
    1. Create a secret using the username and password of sourcedb, 
       1. name the secret as - sm_for_srcdb and 
    2. Create a secret using the endpoint and port of sourcedb, 
       1. name the secret as - sm_for_hostep_and_port_for_srcdb
    3. This will avoid any database connect value hardcoding in clear text in code 

13. Using AWS Console → IAM
    1. Create a new IAM Policy for the Instance Role to be able to access the secrets just created above  
    2. Click on the Create Policy on Top right hand side corner
    3. Under Service type Secret Manager and under Actions Allowed select Read (All Read Actions)
    4. Under the Resources specify the ARNs of all 4 Secrets created (the ones for Target Database as well as the 2 for sourcedb)
    5. Once the policy is created the Json for the policy will look as follows (xxxxx will be the unique value system generated for the secret)
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
    6. Attach the Policy to the IAM instance role - This allows the Instance profile to access the secrets manager

<img width="1315" alt="Image (10)" src="https://github.com/user-attachments/assets/69432a01-d8ff-43a2-93c8-7ffa944d02c6" />


## Setup the Ec2 Instance with Nitro Enclave

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
                        "Resource": [
                            "arn:aws:secretsmanager:<region>:<account-id>:secret:mstestdbsec_enc-xxxxx",
                            "arn:aws:secretsmanager:<region>:<account-id>:secret:sm_for_pgtestdb-xxxxx",
                            "arn:aws:secretsmanager:<region>:<account-id>:secret:sm_for_hostep_and_port_for_srcdb-xxxxx",
                            "arn:aws:secretsmanager:<region>:<account-id>:secret:sm_for_srcdb-xxxxx"
                            ]
                        }
                    ]
                }
      
    5. Attach the Policy to the IAM instance role - This allows the Instance profile to access the secrets manager
       
8.  **Download and Package the RDS CA certificate Bundle**
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
    3. Start the vsock proxies proxies in background as follows
       ```
       sudo vsock-proxy 8000 mstestdb.c23cswqvzlga.us-east-1.rds.amazonaws.com 3306 &
       sudo vsock-proxy 8001 mstestdb3.c23cswqvzlga.us-east-1.rds.amazonaws.com 3306 &
       sudo vsock-proxy 8002 pgtestdb.c23cswqvzlga.us-east-1.rds.amazonaws.com 5432 &
       sudo vsock-proxy 7000 kms.us-east-1.amazonaws.com 443 &
       ```
13. **Update Dockerfile.server:**
    1. Download and Modify the Dockerfile.server and run.sh script located in the src folder as needed
       
14. **Build the enclave:**
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
       
15. **Update the KMS key Policy:**
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
    
16. **Send a request to the server application from Client:**
    1. In a separate terminal window go to the same folder and execute the following command (enclave cid is a 2 digit number seen visible after executing the enclave describe command)
```
    cd aws-nitro-enclaves-samples/vsock_sample/py
    python3 client.py client $ENCLAVECID 5000 --------- Replace ENCLAVECID with the 2 digit EnclaveCID value from previous step
```

18. **Observe the output:**
    1. The console should display the values extracted from the RDS instance. In a real-world scenario, it will send a confirmation if sensitive data is detected.

19. **Clean the environment:**
    1. Delete the Secrets Manager instance
    2. Delete the KMS key
    3. Terminate the RDS instance and
    4. Terminate the Ec2 instance
