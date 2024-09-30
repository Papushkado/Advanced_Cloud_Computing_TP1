import asyncio
import boto3
import os
import time
from utils.benchmarking import get_public_ip, run_benchmark
from utils.ec2_instances_launcher import launch_ec2_instance, shutdown_running_instances
from utils.create_key_pair import generate_key_pair
from utils.create_security_group import create_security_group
from utils.run_command_on_instance import run_command_on_ec2
from utils.upload_content_to_instance import upload_files_to_instances
from dotenv import load_dotenv

from instances_ressources.workers.bootstrap import get_user_data
from instances_ressources.load_balancer.bootstrap import get_lb_user_data



os.environ.pop('AWS_ACCESS_KEY_ID', None)
os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
os.environ.pop('AWS_SESSION_TOKEN', None)
# Load .env file
load_dotenv(dotenv_path='./.env')

# Retrieve AWS credentials from .env file
aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_session_token = os.getenv('AWS_SESSION_TOKEN')
print(aws_access_key_id)

key_pair_name = 'log8415E-tp1-key-pair'
# Create EC2 client
ec2 = boto3.client('ec2',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    aws_session_token = aws_session_token,
    region_name = "us-east-1"
)

key_pair_path = generate_key_pair(ec2, key_pair_name)

group_id = create_security_group(ec2, "log8415E-tp1-security-group", "none")


worker_user_data = get_user_data()
private_instance_cluster0 = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.micro", 
    public_ip=True, # for now because when private lb cant communicate to it. Not sure how to fix. Look at it last
    user_data = worker_user_data, 
    tag=("CLUSTER", "0"), 
    num_instances=4) #TODO PUT CORRECT NUMBER OF INSTANCES

private_instance_cluster1 = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.large",  #TODO PUT CORRECT TYPE OF INSTANCE
    public_ip=True, # for now because when private lb cant communicate to it. Look at it last
    user_data = worker_user_data, 
    tag=("CLUSTER", "1"),
    num_instances=4) #TODO PUT CORRECT NUMBER OF INSTANCES


lb_user_data = get_lb_user_data(aws_access_key_id, aws_secret_access_key, aws_session_token)
lb_instance = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.micro",  #TODO PUT CORRECT TYPE OF INSTANCE
    public_ip=True, 
    user_data = lb_user_data,
    tag=("Name", "load_balancer"),
    num_instances=1)

lb_instance_id = lb_instance[0][0]
time.sleep(300)

#TODO:
#get public ip adress from lb instance id

# Retrieve load balancer public IP and run the benchmark
lb_public_ip = get_public_ip(ec2, lb_instance_id)
print(f"Load Balancer Public IP: {lb_public_ip}")

# Run the benchmark
asyncio.run(run_benchmark(lb_public_ip))

#run benchmark and send command to /cluster1 and /cluster2
#   get back results needed in the report. Check what are those in the énoncé
# 
# cleanup instances, security group, keypair 

##### In this part, we are going to clean_up, all the set up environnement

def terminate_instances(ec2, instance_ids):
    response = ec2.terminate_instances(InstanceIds=instance_ids)
    return response

def delete_key_pair(ec2, key_name):
    response = ec2.delete_key_pair(KeyName=key_name)
    return response

def delete_security_group(ec2, group_id):
    response = ec2.delete_security_group(GroupId=group_id)
    return response

def clean_up(ec2, instance_ids, key_name, group_id):
    
    terminate_instances(ec2,instance_ids)
    time.sleep(400) # We wait 1mn30 to be sure that the instances are deleted
    delete_key_pair(ec2,key_name)
    time.sleep(60) # We wait 30s to be sure that the key_pairs are deleted
    delete_security_group(ec2, group_id) # We need all the instances to be deleted before deleting the security group
    
    
instance_ids = [private_instance_cluster0[0][0], private_instance_cluster1[0][0], lb_instance_id]
clean_up(ec2, instance_ids, key_pair_name, group_id)