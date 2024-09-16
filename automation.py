import boto3
import time
import paramiko
import os

# Variables
KEY_NAME = "aws_key_log"
SECURITY_GROUP = "sg-079f6fc3980ae2c24"
IMAGE_ID = "ami-0e86e20dae9224db8"
INSTANCE_TYPE_T2_MICRO = "t2.micro"
INSTANCE_TYPE_T2_LARGE = "t2.large"
LB_NAME = "fastapi-load-balancer"
TG_NAME_CLUSTER1 = "cluster1-micro"
TG_NAME_CLUSTER2 = "cluster2-large"
REGION = "us-east-1"
VPC_ID = "vpc-0085fffff3cf0af11"
SUBNETS = ["subnet-xxxxxxx", "subnet-yyyyyyy"]
USER_DATA = '''#!/bin/bash
sudo apt update
sudo apt install -y python3-pip
pip3 install fastapi uvicorn
echo '
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello World from FastAPI"}
' > app.py
uvicorn app:app --host 0.0.0.0 --port 8000 &
'''

# Initialize boto3 clients
ec2 = boto3.client('ec2', region_name=REGION)
elbv2 = boto3.client('elbv2', region_name=REGION)

# Step 1: Create EC2 instances
def create_instances():
    instance_ids_micro = []
    instance_ids_large = []

    print("Launching EC2 instances...")

    for i in range(4):
        instances = ec2.run_instances(
            ImageId=IMAGE_ID,
            InstanceType=INSTANCE_TYPE_T2_MICRO,
            KeyName=KEY_NAME,
            SecurityGroupIds=[SECURITY_GROUP],
            MinCount=1,
            MaxCount=1,
            UserData=USER_DATA,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': f't2micro-instance-{i + 1}'}]
            }]
        )
        instance_ids_micro.append(instances['Instances'][0]['InstanceId'])

    for i in range(4):
        instances = ec2.run_instances(
            ImageId=IMAGE_ID,
            InstanceType=INSTANCE_TYPE_T2_LARGE,
            KeyName=KEY_NAME,
            SecurityGroupIds=[SECURITY_GROUP],
            MinCount=1,
            MaxCount=1,
            UserData=USER_DATA,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': f't2large-instance-{i + 1}'}]
            }]
        )
        instance_ids_large.append(instances['Instances'][0]['InstanceId'])

    print("EC2 instances launched successfully.")
    return instance_ids_micro, instance_ids_large

# Step 2: Create Load Balancer and Target Groups
def create_load_balancer():
    print("Creating Application Load Balancer and Target Groups...")

    # Create target groups
    tg1 = elbv2.create_target_group(
        Name=TG_NAME_CLUSTER1,
        Protocol='HTTP',
        Port=8000,
        VpcId=VPC_ID,
        HealthCheckPath='/',
        TargetType='instance'
    )
    tg2 = elbv2.create_target_group(
        Name=TG_NAME_CLUSTER2,
        Protocol='HTTP',
        Port=8000,
        VpcId=VPC_ID,
        HealthCheckPath='/',
        TargetType='instance'
    )
    
    # Create Load Balancer
    lb = elbv2.create_load_balancer(
        Name=LB_NAME,
        Subnets=SUBNETS,
        SecurityGroups=[SECURITY_GROUP],
        Scheme='internet-facing',
        Type='application'
    )

    lb_arn = lb['LoadBalancers'][0]['LoadBalancerArn']
    tg_arn1 = tg1['TargetGroups'][0]['TargetGroupArn']
    tg_arn2 = tg2['TargetGroups'][0]['TargetGroupArn']

    print(f"Load Balancer ARN: {lb_arn}")
    print(f"Target Group 1 ARN: {tg_arn1}")
    print(f"Target Group 2 ARN: {tg_arn2}")
    
    # Wait for load balancer to be active
    waiter = elbv2.get_waiter('load_balancer_available')
    waiter.wait(LoadBalancerArns=[lb_arn])

    return lb_arn, tg_arn1, tg_arn2

# Step 3: Register Instances with Target Groups
def register_instances_to_target_groups(instance_ids_micro, instance_ids_large, tg_arn1, tg_arn2):
    print("Registering instances with Target Groups...")

    for instance_id in instance_ids_micro:
        elbv2.register_targets(
            TargetGroupArn=tg_arn1,
            Targets=[{'Id': instance_id}]
        )

    for instance_id in instance_ids_large:
        elbv2.register_targets(
            TargetGroupArn=tg_arn2,
            Targets=[{'Id': instance_id}]
        )

    print("Instances registered successfully.")

# Step 4: Create Listener
def create_listener(lb_arn, tg_arn1, tg_arn2):
    print("Creating Listener and setting up rules...")

    elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[{
            'Type': 'forward',
            'TargetGroupArn': tg_arn1
        }]
    )
    
    print("Listener created successfully.")

# Step 5: Benchmarking using HTTP requests
def benchmark_load_balancer(lb_dns):
    import requests
    from concurrent.futures import ThreadPoolExecutor

    def make_request(i):
        response = requests.get(f'http://{lb_dns}')
        return response.status_code, response.elapsed.total_seconds()

    print(f"Running benchmark against Load Balancer {lb_dns}...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(make_request, range(1000)))

    total_time = sum([res[1] for res in results])
    avg_time = total_time / len(results)

    print(f"Total time taken: {total_time:.2f} seconds")
    print(f"Average time per request: {avg_time:.4f} seconds")

# Main function to coordinate all steps
def main():
    instance_ids_micro, instance_ids_large = create_instances()
    lb_arn, tg_arn1, tg_arn2 = create_load_balancer()
    register_instances_to_target_groups(instance_ids_micro, instance_ids_large, tg_arn1, tg_arn2)
    create_listener(lb_arn, tg_arn1, tg_arn2)

    # Retrieve Load Balancer DNS
    lb_dns = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]['DNSName']
    print(f"Load Balancer DNS: {lb_dns}")

    # Sleep for a while to ensure instances are fully up and running
    time.sleep(120)  # Wait 2 minutes before benchmarking
    
    benchmark_load_balancer(lb_dns)

if __name__ == "__main__":
    main()
