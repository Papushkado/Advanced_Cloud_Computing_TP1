import boto3
import time
import paramiko
from botocore.exceptions import ClientError

# Variables
KEY_NAME = "my-aws-key"
SECURITY_GROUP_NAME = "tp1"
IMAGE_ID = "ami-0e86e20dae9224db8"  
INSTANCE_TYPE_T2_MICRO = "t2.micro"
INSTANCE_TYPE_T2_LARGE = "t2.large"
REGION = "us-east-1"
LOAD_BALANCER_NAME = "fastapi-load-balancer"
VPC_ID = "vpc-0085fffff3cf0af11"

# FastAPI app content
MAIN_PY_CONTENT = """
from fastapi import FastAPI
import uvicorn
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI()

# Get instance ID (you can pass this as an environment variable for each instance)
instance_id = os.getenv("INSTANCE_ID", "Unknown Instance")

@app.get("/")
async def root():
    message = f"Instance {instance_id} has received the request"
    logger.info(message)
    return {"message": message}

@app.get("/cluster1")
async def cluster1():
    message = f"Cluster 1 - Instance {instance_id} is responding now!"
    logger.info(message)
    return {"message": message}

@app.get("/cluster2")
async def cluster2():
    message = f"Cluster 2 - Instance {instance_id} is responding now!"
    logger.info(message)
    return {"message": message}

if __name__ == "__main__":
    # Run the FastAPI app
    uvicorn.run(app, host="0.0.0.0", port=8000)
"""

USER_DATA = f"""#!/bin/bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install python3 python3-pip -y
sudo pip3 install fastapi uvicorn
echo '{MAIN_PY_CONTENT}' > main.py
uvicorn main:app --host 0.0.0.0 --port 8000 &
"""

# Initialize boto3 clients
ec2 = boto3.client('ec2', region_name=REGION)

def create_key_pair():
    try:
        response = ec2.create_key_pair(KeyName=KEY_NAME)
        with open(f"{KEY_NAME}.pem", "w") as file:
            file.write(response['KeyMaterial'])
        print(f"Key pair {KEY_NAME} created and saved.")
    except ClientError as e:
        print(f"Key pair {KEY_NAME} already exists: {e}")
        
        

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
        

def launch_instances(instance_type, count, security_group_id):
    instances = ec2.run_instances(
        ImageId=IMAGE_ID,
        InstanceType=instance_type,
        KeyName=KEY_NAME,
        MinCount=count,
        MaxCount=count,
        SecurityGroupIds=[security_group_id],
        UserData=USER_DATA,
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': [{'Key': 'Purpose', 'Value': 'FastAPI'}]
        }]
    )
    instance_ids = [instance['InstanceId'] for instance in instances['Instances']]
    return instance_ids

def main():
    create_key_pair()
    security_group_id = create_security_group()

    # Lance kles instnaces
    micro_instances = launch_instances(INSTANCE_TYPE_T2_MICRO, 1, security_group_id) # Remplacer 1 par 4 pour avoir le bon nombre
    large_instances = launch_instances(INSTANCE_TYPE_T2_LARGE, 1, security_group_id) # Remplacer 1 par 4 pour avoir le bon nombre
    
main()