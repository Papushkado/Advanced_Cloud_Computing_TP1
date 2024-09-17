"""Script to launch EC2 instances."""
def launch_ec2_instance(ec2, 
                    key_pair_name, 
                    security_group_id,
                    instance_type:str = "t2.micro", 
                    num_instances:int = 1, 
                    image_id:str =  "ami-0e86e20dae9224db8",
                    public_ip:bool = False,
                    allow_ssh:bool = True
                    ):
    # Create EC2 client
    # Specify instance parameters
    instance_params = {
        'ImageId': image_id,  # Amazon Linux 2 AMI ID (us-east-1)
        'InstanceType': instance_type,
        'MinCount': num_instances,
        'MaxCount': num_instances,
        "SecurityGroupIds": [security_group_id],
        'KeyName': key_pair_name,  # Replace with your key pair name
        'NetworkInterfaces': [{
            'AssociatePublicIpAddress': public_ip,
            'DeviceIndex': 0,
            'Groups': []
        }]
    }

    if allow_ssh:
        instance_params['NetworkInterfaces'][0]['Groups'].append('sg-xxxxxxxx')  # Replace with your security group ID that allows SSH

    # Launch the instance
    print("Launching instances...")
    response = ec2.run_instances(**instance_params)



    # Get the instance ID
    instances_id_and_ip = []
    print("Waiting for instances to be running...")
    for instance in response['Instances']:
        instance.wait_until_running()
        instance_id = instance['InstanceId']
        if not public_ip:
            instances_id_and_ip.append((instance_id, instance.private_ip_address))
        else:
            instances_id_and_ip.append((instance_id, instance.public_ip_address))

    print(f"Launched {num_instances} EC2 instances of type {instance_type} with ID and ip: {instances_id_and_ip}")

    return instances_id_and_ip