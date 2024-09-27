import boto3
import os
import time
from utils.ec2_instances_launcher import launch_ec2_instance, shutdown_running_instances
from utils.create_key_pair import generate_key_pair
from utils.create_security_group import create_security_group
from utils.run_command_on_instance import run_command_on_ec2
from utils.upload_content_to_instance import upload_files_to_instances
from dotenv import load_dotenv

from instances_ressources.workers.bootstrap import get_user_data
from instances_ressources.load_balancer.bootstrap import get_lb_user_data

# Retrieve AWS credentials from .env file

load_dotenv()

aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_session_token = os.getenv('AWS_SESSION_TOKEN')

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
    num_instances=1) #TODO PUT CORRECT NUMBER OF INSTANCES

private_instance_cluster1 = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.micro",  #TODO PUT CORRECT TYPE OF INSTANCE
    public_ip=True, # for now because when private lb cant communicate to it. Look at it last
    user_data = worker_user_data, 
    tag=("CLUSTER", "1"),
    num_instances=1) #TODO PUT CORRECT NUMBER OF INSTANCES


lb_user_data = get_lb_user_data(aws_access_key_id, aws_secret_access_key, aws_session_token)
lb_instance = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.micro",  #TODO PUT CORRECT TYPE OF INSTANCE
    public_ip=True, 
    user_data = lb_user_data,
    num_instances=1)

lb_instance_id = lb_instance[0][0]
time.sleep(300)

#TODO:
#get public ip adress from lb instance id
#run benchmark and send command to /cluster1 and /cluster2
#   get back results needed in the report. Check what are those in the énoncé
# 
# cleanup instances, security group, keypair 


##### In this part, we are going to clean_up, all the set up environnement

def terminate_instances(ec2, instance_ids):
    response = ec2.terminate_instances(instance_ids=instance_ids)
    return response

def delete_key_pair(ec2, key_name):
    response = ec2.delete_key_pair(KeyName=key_name)
    return response

def delete_security_group(ec2, group_id):
    response = ec2.delete_security_group(group_id=group_id)
    return response

def clean_up(ec2, instance_ids, key_name, group_id):
    
    terminate_instances(ec2,instance_ids)
    delete_key_pair(ec2,key_name)
    delete_security_group(ec2, group_id)
    
instance_ids = [private_instance_cluster0[0][0], private_instance_cluster1[0][0], lb_instance_id]
clean_up(ec2, instance_ids, key_pair_name, group_id)