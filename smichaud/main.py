import boto3
import os
from utils.ec2_instances_launcher import launch_ec2_instance

# Retrieve AWS credentials from environment variables
aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
aws_session_token = os.environ.get('AWS_SESSION_TOKEN')
print(aws_access_key_id)
print(aws_secret_access_key)

def generate_key_pair(ec2_client, key_pair_name):
    # Generate a key pair
    
    response = ec2_client.create_key_pair(KeyName=key_pair_name)

    # Save the private key to a file
    private_key = response['KeyMaterial']
    with open(f'{key_pair_name}.pem', 'w') as key_file:
        key_file.write(private_key)

    print(f"Key pair '{key_pair_name}' has been created and saved to {key_pair_name}.pem")

    return response

key_pair_name = 'log8415E-tp1-key-pair'
# Create EC2 client
ec2 = boto3.client('ec2',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    aws_session_token = aws_session_token,
    region_name = "us-east-1"
)

generate_key_pair(ec2, key_pair_name)
instances_id = launch_ec2_instance(ec2, key_pair_name)

