import boto3
import time
import paramiko
from botocore.exceptions import ClientError

# Variables
KEY_NAME = "my-aws-key"
SECURITY_GROUP_NAME = "tp1_security"
IMAGE_ID = "ami-0e86e20dae9224db8"  
INSTANCE_TYPE_T2_MICRO = "t2.micro"
INSTANCE_TYPE_T2_LARGE = "t2.large"
REGION = "us-east-1"
LOAD_BALANCER_NAME = "fastapi-load-balancer"
VPC_ID = "vpc-0085fffff3cf0af11"

# Initialize boto3 clients
ec2 = boto3.client('ec2', region_name=REGION)
elb = boto3.client('elb', region_name=REGION)

def create_security_group():
    try:
        response = ec2.create_security_group(
            GroupName=SECURITY_GROUP_NAME,
            Description="Security group for FastAPI instances",
            VpcId=VPC_ID
        )
        security_group_id = response['GroupId']
        print(f"Security group {SECURITY_GROUP_NAME} created.")
        
        ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Allow SSH
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 8000,
                    'ToPort': 8000,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Allow FastAPI
                }
            ]
        )
        return security_group_id
    except ClientError as e:
        print(f"Security group already exists: {e}")
        
create_security_group()