import os
import paramiko

def upload_files_to_instances(ec2, instances, key_pair_path, source_folder, out_path = "log8415e"):

    for instance_id, instances_ip in instances:
        instance = ec2.Instance(instance_id)
        
        # Get the public IP address of the instance
        instance.load()
        
        
        ssh = paramiko.SSHClient()
        # Set up SSH client
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Connect to the instance
            ssh.connect(instances_ip, username='', key_filename=key_pair_path)
            
            # Create SFTP client
            sftp = ssh.open_sftp()
            
            # Upload files
            for root, dirs, files in os.walk(source_folder):
                for file in files:
                    local_path = os.path.join(root, file)
                    remote_path = os.path.join(f'/home/{out_path}')
                    
                    # Create remote directories if they don't exist
                    remote_dir = os.path.dirname(remote_path)
                    sftp.mkdir(remote_dir, ignore_existing=True)
                    
                    # Upload the file
                    sftp.put(local_path, remote_path)
                    print(f"Uploaded {local_path} to {instance_id}:{remote_path}")
            
            sftp.close()
            ssh.close()
            
        except Exception as e:
            print(f"Error uploading to instance {instance_id}: {str(e)}")