
import paramiko
import boto3

def run_command_on_ec2(ec2, instance_id, key_pair_path, command):

    # Get instance details
    instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
    public_ip = instance['PublicIpAddress']

    # Initialize SSH client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the instance
        ssh.connect(hostname=public_ip, username='ec2-user', key_filename=key_pair_path)

        # Execute the command
        stdin, stdout, stderr = ssh.exec_command(command)

        # Get the output
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        return output, error
    except Exception as e:
        return None, str(e)
    finally:
        ssh.close()
