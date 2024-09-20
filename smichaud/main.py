import boto3
import os
import time
from utils.ec2_instances_launcher import launch_ec2_instance
from utils.create_key_pair import generate_key_pair
from utils.create_security_group import create_security_group
from utils.run_command_on_instance import run_command_on_ec2

from instances_ressources.workers.bootstrap import USER_DATA
from instances_ressources.load_balancer.bootstrap import START_COMMAND, LOAD_BALANCER_USER_DATA

# Retrieve AWS credentials from environment variables
# TODO LOAD FROM FILE
aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
aws_session_token = os.environ.get('AWS_SESSION_TOKEN')

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

private_instance_cluster0 = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.micro", 
    public_ip=False, 
    user_data = USER_DATA, 
    tag=("CLUSTER", "0"), 
    num_instances=1)

private_instance_cluster1 = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.micro", 
    public_ip=False, 
    user_data = USER_DATA, 
    tag=("CLUSTER", "1"),
    num_instances=1)


#TODO ADD MAIN.PY TO FILES or Upload it using uplaod_content_to_instance
lb_instance = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.micro", 
    public_ip=True, 
    user_data = LOAD_BALANCER_USER_DATA.format(
        aws_access_key_id, 
        aws_secret_access_key, 
        aws_session_token),
    num_instances=1)
lb_instance = lb_instance[0]

#todo:
# check if tag is working.
#   check if we can correctly list instances based on tag
# fix script load for workers
# upload key, credentials and script to lb
# start lb

#benchmark...

# time.sleep(120)
#TODO 
# run_command_on_ec2(ec2, lb_instance[0], key_pair_path=key_pair_path, command= START_COMMAND)


#start benchmarking

#




