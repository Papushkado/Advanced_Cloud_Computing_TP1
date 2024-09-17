import boto3
import time
import paramiko
from botocore.exceptions import ClientError

# Variables
KEY_NAME = "my-aws-key"
SECURITY_GROUP_NAME = "sg-079f6fc3980ae2c24"
IMAGE_ID = "ami-0e86e20dae9224db8"  
INSTANCE_TYPE_T2_MICRO = "t2.micro"
INSTANCE_TYPE_T2_LARGE = "t2.large"
REGION = "us-east-1"
LOAD_BALANCER_NAME = "fastapi-load-balancer"
VPC_ID = "vpc-0085fffff3cf0af11"

# Initialize boto3 clients
ec2 = boto3.client('ec2', region_name=REGION)
elb = boto3.client('elb', region_name=REGION)

def create_key_pair():
    try:
        response = ec2.create_key_pair(KeyName=KEY_NAME)
        with open(f"{KEY_NAME}.pem", "w") as file:
            file.write(response['KeyMaterial'])
        print(f"Key pair {KEY_NAME} created and saved.")
    except ClientError as e:
        print(f"Key pair {KEY_NAME} already exists: {e}")
        
        
create_key_pair()