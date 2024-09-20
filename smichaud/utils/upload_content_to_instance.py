import os
import paramiko

def upload_files_to_instances(ec2, instance_id, key_pair_path, source_folder):

    ssh = paramiko.SSHClient()
    privkey = paramiko.RSAKey.from_private_key_file(key_pair_path)
    # Set up SSH client
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
    public_ip = instance['PublicIpAddress']

    if public_ip is None or len(public_ip) == 0:
        print(f"No public IP address found for instance {instance_id}")
        return
    
    try:
        # Connect to the instance

        ssh.connect(public_ip, username='ubuntu', pkey=privkey)
        
        # Create SFTP client
        sftp = ssh.open_sftp()
        
        # Upload files
        for root, _, files in os.walk(source_folder):
            for file in files:
                local_path =  os.path.join(root, file)
                remote_path = os.path.join(f'{file}')
                
                # Upload the file
                sftp.put(local_path, remote_path)
            print(f"Uploaded {local_path} to {instance_id}")
        
        sftp.close()
        ssh.close()
        
    except Exception as e:
        print(f"Error uploading to instance {instance_id}: {str(e)}, {type(e)}")