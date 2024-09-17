import boto3
import os
from utils.ec2_instances_launcher import launch_ec2_instance
from utils.create_key_pair import generate_key_pair
from utils.create_security_group import create_security_group
from utils.upload_content_to_instances import upload_files_to_instances

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
instances_id_ip = launch_ec2_instance(ec2, key_pair_name, group_id, "t2.micro", public_ip=True)

upload_files_to_instances(ec2, instances_id_ip, key_pair_path, "instances_ressources", "log8415e")

