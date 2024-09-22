# Need to allow ssh to all machines
import boto3
import os


def create_security_group(ec2_client, group_name, group_description):
    # Check if security group already exists
    existing_groups = ec2_client.describe_security_groups(
        Filters=[
            {'Name': 'group-name', 'Values': [group_name]}
        ]
    )['SecurityGroups']

    if existing_groups:
        # If the group exists, return its ID
        print(f"Security group '{group_name}' already exists.")
        return existing_groups[0]['GroupId']

    # If the group doesn't exist, create a new one
    # Get default VPC ID
    print("Creating security group...")
    default_vpc = ec2_client.describe_vpcs()['Vpcs'][0]['VpcId']

    response = ec2_client.create_security_group(
        GroupName=group_name,
        Description=group_description,
        VpcId=default_vpc
    )

    group_id = response['GroupId']

    ec2_client.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Allow SSH
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Allow FastAPI
            },
            {
                'IpProtocol': 'tcp',
                'FromPort': 443,
                'ToPort': 443,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Allow HTTPS
            },
            {
                'IpProtocol': 'icmp',
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Allow ICMP
            }
        ]
    )
    print("Security group created successfully.")
    return group_id