# Need to allow ssh to all machines
import boto3
import os


def create_security_group(ec2_client, group_name, group_description):
    # Create a security group

    
    # Get default VPC ID
    default_vpc = ec2_client.describe_vpcs()['Vpcs'][0]['VpcId']
    

    response = ec2_client.create_security_group(
        GroupName=group_name,
        Description=group_description,
        VpcId = default_vpc
    )

    group_id = response['GroupId']

    #todo verify this
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
                    'FromPort': 8000,
                    'ToPort': 8000,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]  # Allow FastAPI
                }
            ]
        )

    return group_id