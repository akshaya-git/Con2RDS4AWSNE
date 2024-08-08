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
1. Setup your Nitro Enclave environment
    1. Create a EC2 machine with Nitro Enclave enabled and 50gb of storage (This can be done from console or using Cli command)
2. Create a KMS Key (use console - You can provide your own key material if needed but for this test we will use AWS generated CMK)
    1. Note the ARN of the key for future use
3. Create a MySQL RDS instance (use console to create the DB) 
    1. Note the ARN of the Database (you can optionally enable TLS on RDS database but this example does not use TLS certificate during RDS requests)
    2. Note the username / password provided when creating the RDS instances for future use
4. Install Docker and Nitro Enclave Cli on the Ec2 machine — https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html
5. Update the Memory allocation for NitroEnclave
      sudo systemctl stop nitro-enclaves-allocator.service
      sudo vi /etc/nitro_enclaves/allocator.yaml
      update the --- memory_mib: 8000 and save the file
      sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
6. Install the sample vsock Hello world application - Connect to ec2 instance - Install git and clone the git repo - 
      git clone https://github.com/aws/aws-nitro-enclaves-samples.git
      cd aws-nitro-enclaves-samples/vsock_sample/py
7. Prepare the Secrets Manager with encrypted RDS Credentials
    1. Encrypt your RDS username and Password using the sample Script  
    2. Create a new Secret Manager using the encrypted username and password provided by the script above - Use AWS console to create a new secret manager entry
    3. Create a new Policy for the Instance Role to be able to access the secret manager
    4. Attach the Policy to the IAM instance role - This allows the Instance profile to access the secrets manager
8. Deploy kmstool-enclave-cli - https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/main/bin/kmstool-enclave-cli
    1. Move the kms_enclave_cli file and libnsm.so file under aws-nitro-enclaves-samples/vsock_sample/py folder for the Dockerfile.server to access them during the build process
    2. This tool allows Enclave to connect to KMS for decryption of RDS credentials
9. Install the traffic forwarder to forward request from inside Enclave to RDS to query the data - https://github.com/aws-samples/aws-nitro-enclaves-workshop/blob/8e48f98f6923aff725f37ca7099b16da86251aca/resources/code/my-first-enclave/secure-local-channel/traffic_forwarder.py
    1. Copy the forwarder code and paste it in a file under aws-nitro-enclaves-samples/vsock_sample/py folder - retain the name of the file as traffic_forwarder.py 
    2. Update the Dockerfile and run.sh as captured in steps below
10. Update the client.py and server.py code 
11. Install and build the vsock Proxy - https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md
    1. Update the /etc/nitro_enclaves/vsock-proxy.yaml file and make the following entry at the top of the file (follow the indentation pattern as it is set for other entires)
        1. -- {address: <RDS Endpoint ARN>, port: 3306}
    2. Start the 2 vsock proxies proxies in background as follows
        1. vsock-proxy 8000 mstestdb.c23cswqvzlga.us-east-1.rds.amazonaws.com 3306 &
        2. vsock-proxy 7000 kms.us-east-1.amazonaws.com 443 &
12. Update the Dockerfile.server 
13. Update the run.sh script 
14. Build the enclave - Build the Docker image, build the enclave image file, build the enclave, start the Enclave and connect to the console - Note to run the enclave in production mode remove the —debug-mode —attach-console parameter
        nitro-cli terminate-enclave —all
        docker rmi vsock-sample-server:latest
        rm vsock_sample_server.eif
        docker build -t vsock-sample-server -f Dockerfile.server .
        nitro-cli build-enclave —docker-uri vsock-sample-server —output-file vsock_sample_server.eif
        nitro-cli run-enclave —eif-path vsock_sample_server.eif —cpu-count 2 —memory 6000 
15. Send a request to the server application from Client - In a separate terminal window go to the same folder and execute the following command (enclave cid is a 2 digit number seen visible after executing the enclave describe command)
        cd aws-nitro-enclaves-samples/vsock_sample/py
        python3 client.py client $ENCLAVE_CID 5000
16. Observe the output - The console on the step 12 should show the values extracted from RDS instance and teh same RDS extracted values should be visible on client terminal 
17. Update the KMS key Policy with Instance admin role and PCR0 value of the Enclave, this will lock down the access to KMS key only to Enclave (Note the enclave has to be started in production mode for this option to work)
        1. Add following roles as Key administrators
            1. Ec2 instances role (In my case that was EpoxyChronicleInstanceRole)
            2. Admin
18. Clean the environment
    1. Delete the Secrets Manager
    2. Delete the KMS key
    3. Terminate the RDS instance and
    4. Terminate the Ec2 instance
