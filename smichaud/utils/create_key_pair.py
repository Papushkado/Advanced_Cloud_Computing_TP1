import boto3
import os
def generate_key_pair(ec2_client, key_pair_name):
    # Generate a key pair
    
    response = ec2_client.create_key_pair(KeyName=key_pair_name)

    # Save the private key to a file
    private_key = response['KeyMaterial']
    with open(f'{key_pair_name}.pem', 'w') as key_file:
        key_file.write(private_key)

    print(f"Key pair '{key_pair_name}' has been created and saved to {key_pair_name}.pem")

    return response