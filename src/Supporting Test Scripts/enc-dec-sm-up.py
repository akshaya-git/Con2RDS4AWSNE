import base64
import boto3
import mysql.connector
import json

# Specify your AWS region
aws_region = 'us-east-1'


# Initialize AWS KMS client with the specified region
kms_client = boto3.client('kms', region_name=aws_region)


# KMS Key ID or ARN
kms_key_id = 'arn:aws:kms:us-east-1:<accountid>:<KMS Key>'


# The plaintext string you want to encrypt
user = '<username>'
password = '<password>'

# Convert the plaintext string to bytes
plaintext_user = user.encode('utf-8')
plaintext_password = password.encode('utf-8')

# Encrypt the plaintext using KMS
respuser = kms_client.encrypt(
 KeyId=kms_key_id,
 Plaintext=plaintext_user
)

# Encrypt the plaintext using KMS
resppass = kms_client.encrypt(
 KeyId=kms_key_id,     
 Plaintext=plaintext_password
)

# Get the encrypted data (ciphertext blob)
ciphertext_user = respuser['CiphertextBlob']

# Get the encrypted data (ciphertext blob)
ciphertext_pass = resppass['CiphertextBlob']

# Optionally, encode the ciphertext blob to base64 for storage or transmission
ciphertext_u_base64 = base64.b64encode(ciphertext_user).decode('utf-8')

# Optionally, encode the ciphertext blob to base64 for storage or transmission
ciphertext_p_base64 = base64.b64encode(ciphertext_pass).decode('utf-8')

# Print the base64-encoded encrypted string
print("Encrypted User", ciphertext_u_base64)
print("Encrypted Password:", ciphertext_p_base64)

#Test the decryption
# Base64-encoded encrypted string
encrypted_user = str(ciphertext_u_base64) 
encrypted_pass = str(ciphertext_p_base64)

# Decode the base64-encoded encrypted string to get the ciphertext
encrypted_u_bytes = base64.b64decode(encrypted_user)
encrypted_p_bytes = base64.b64decode(encrypted_pass) 

# Decrypt the ciphertext using KMS for user
decrypt_response_u = kms_client.decrypt(
    CiphertextBlob=encrypted_u_bytes
)

# Decrypt the ciphertext using KMS for pass
decrypt_response_p = kms_client.decrypt(
    CiphertextBlob=encrypted_p_bytes
)

# Extract the decrypted plaintext
decrypted_u_bytes = decrypt_response_u['Plaintext']
decrypted_u_string = decrypted_u_bytes.decode('utf-8')
print("Decrypted user:", decrypted_u_string)


# Extract the decrypted plaintext
decrypted_p_bytes = decrypt_response_p['Plaintext']
decrypted_p_string = decrypted_p_bytes.decode('utf-8')
print("Decrypted pass:", decrypted_p_string)
