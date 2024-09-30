# FastAPI Benchmark and Deployment Report

---
- [FastAPI Benchmark and Deployment Report](#fastapi-benchmark-and-deployment-report)
  - [FastAPI Deployment Procedure](#fastapi-deployment-procedure)
    - [Key Pair and Security Group](#key-pair-and-security-group)
    - [Worker Instances Setup](#worker-instances-setup)
    - [Load Balancer Deployment](#load-balancer-deployment)
  - [Cluster Setup Using Application Load Balancer](#cluster-setup-using-application-load-balancer)
    - [Tagging and Instance Management](#tagging-and-instance-management)
  - [Benchmark Results](#benchmark-results)
    - [Expectations](#expectations)
    - [CPU Utilization](#cpu-utilization)
    - [Latency and Response Times](#latency-and-response-times)
    - [Throughput](#throughput)
  - [Instructions to Run code](#instructions-to-run-code)
    - [Prerequisites](#prerequisites)
  - [EC2 Instance Creation](#ec2-instance-creation)
    - [Deploy FastAPI](#deploy-fastapi)
    - [Test tke Load Balancer](#test-tke-load-balancer)
  - [Conclusion](#conclusion)
  - [Appendix](#appendix)
    - [main.py :](#mainpy-)
    - [Folder utils :](#folder-utils-)
    - [Folder instances\_ressources :](#folder-instances_ressources-)
      - [Folder load\_balancer :](#folder-load_balancer-)
      - [Folder workers :](#folder-workers-)

---

## FastAPI Deployment Procedure

### Key Pair and Security Group

The first step in deploying the FastAPI application was **generating an SSH key pair**. This key is essential for securely accessing the EC2 instances. The command `generate_key_pair` was used to create the key, allowing us to securely SSH into the instances.

Additionally, we created a security group (`create_security_group`) to manage the inbound and outbound traffic for our instances. The security group was configured to allow:

- SSH (Port 22) for remote access.
- HTTP/HTTPS (Ports 80, 443) for web traffic.

### Worker Instances Setup

For each worker, we used `get_user_data`, which provides a script that installs essential packages such as Python3, FastAPI, and Uvicorn. The worker instances serve different FastAPI endpoints (_/cluster1_, _/cluster2_) and are part of the cluster used for handling traffic.

Each worker runs the FastAPI application via Uvicorn. The load balancing and clustering were achieved by tagging these instances and distributing the requests based on their CPU load.

### Load Balancer Deployment

The load balancer was set up using `get_lb_user_data`. This script installs dependencies and runs a Python script (`load_balancer.py`) on a dedicated instance to handle traffic distribution between workers. The load balancer:

- Uses responsivness of http requests to determine the cluster with the least load.
- Distributes requests between the clusters based on their responnsiveness.
- This responsiveness is computed every 10 requests.

## Cluster Setup Using Application Load Balancer

We deployed two clusters:

- **Cluster 0:** Instances of type t2.micro.
- **Cluster 1:** Instances of type t2.large.

Each cluster was tagged accordingly, allowing the load balancer to differentiate between them. The load balancer was configured to route traffic between these clusters based on CPU utilization metrics.

### Tagging and Instance Management

Each instance was tagged as part of either Cluster 0 or Cluster 1. The load balancer uses these tags to direct traffic, ensuring that requests are handled efficiently. The custom logic for this was written in Python and deployed on an EC2 instance running the load balancer.

## Benchmark Results 

### Expectations

Before any experiment, we expect that the t2.micro cluster to have higher response time than the t2.large. It is to note however that the workload is not expensive, so the difference in response time might not be significant.
Indeed, the capacity of the virtual machines entail different behaviors regarding the amount of requests. 

### CPU Utilization 


### Latency and Response Times

We tested the latency and response times for each cluster by sending 1000 requests to the load balancer and observing how long each cluster took to respond.

- **t2.micro :**
- **t2.large :**

### Throughput


## Instructions to Run code

### Prerequisites 

To run the FastAPI deployment and benchmark tests, the following prerequisites must be met:

    
- AWS account: Ensure you have an active AWS account with appropriate IAM roles to create EC2 instances and security groups.
- Python 3: Install Python 3.x along with the boto3 library for interacting with AWS services.
- AWS CLI: Install the AWS CLI and configure your credentials with the aws configure command.

## EC2 Instance Creation 

Run the `main.py` script to:

1. Generate the key pair.
2. Create the security group.
3. Launch the EC2 instances (workers and load balancer).
4. Run the benchmark
5. Clean-up all the instances, the key-pair generated and the security-group 

Ensure your AWS credentials are either set up in the environment or passed directly to the script.

### Deploy FastAPI

Once the instances are up, the FastAPI workers will automatically start. You can verify this by sending HTTP requests to the _/cluster1_ or _/cluster2_ endpoints of the workers. For example:
```
curl http://<worker_public_ip>:8000/cluster1
```
### Test tke Load Balancer

To test the load balancer, send requests to its public IP. The load balancer will distribute the traffic to the worker instances based on their current CPU utilization:
```
curl http://<load_balancer_public_ip>
```

## Conclusion 

In this project, we successfully deployed a FastAPI application on AWS EC2 instances, setting up a custom load balancer to manage traffic between two clusters. The performance benchmarks demonstrated the clear advantage of using t2.large instances for high-traffic applications, though t2.micro instances can be useful for low-traffic scenarios.

While the custom load balancer provided granular control over traffic distribution, AWS's managed Elastic Load Balancer (ELB) may offer a more robust and scalable solution for production environments, particularly with features like SSL termination and automatic failover.

## Appendix

### main.py :

Here is the code of main.py :

```
import asyncio
import boto3
import os
import time
from utils.benchmarking import get_public_ip, run_benchmark
from utils.ec2_instances_launcher import launch_ec2_instance
from utils.create_key_pair import generate_key_pair
from utils.create_security_group import create_security_group
from dotenv import load_dotenv

from instances_ressources.workers.bootstrap import get_user_data
from instances_ressources.load_balancer.bootstrap import get_lb_user_data


INSTANCES_INSTALL_DELAY = 500
# Clear environment variables
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
    num_instances=4)

private_instance_cluster1 = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.large",
    public_ip=True, # for now because when private lb cant communicate to it. Look at it last
    user_data = worker_user_data, 
    tag=("CLUSTER", "1"),
    num_instances=4)


lb_user_data = get_lb_user_data(aws_access_key_id, aws_secret_access_key, aws_session_token)
lb_instance = launch_ec2_instance(
    ec2, 
    key_pair_name, 
    group_id, 
    "t2.micro",
    public_ip=True, 
    user_data = lb_user_data,
    tag=("Name", "load_balancer"),
    num_instances=1)

lb_instance_id = lb_instance[0][0]
print("Waiting for instances to finishes installing ...")
time.sleep(INSTANCES_INSTALL_DELAY)
print("Waiting done.")

# Retrieve load balancer public IP and run the benchmark
lb_public_ip = get_public_ip(ec2, lb_instance_id)
print(f"Load Balancer Public IP: {lb_public_ip}")

# Run the benchmark
asyncio.run(run_benchmark(lb_public_ip))

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
    time.sleep(INSTANCES_INSTALL_DELAY) # We wait 1mn30 to be sure that the instances are deleted
    delete_key_pair(ec2,key_name)
    time.sleep(60) # We wait 30s to be sure that the key_pairs are deleted
    delete_security_group(ec2, group_id) # We need all the instances to be deleted before deleting the security group
    
print("\n Cleaning up instances and security group ...")
instance_ids = [private_instance_cluster0[0][0], private_instance_cluster1[0][0], lb_instance_id]
for p in range(len(private_instance_cluster0)):
    instance_ids.append(private_instance_cluster0[p][0])
    instance_ids.append(private_instance_cluster1[p][0])
clean_up(ec2, instance_ids, key_pair_name, group_id)

```
### Folder utils :
Here is the code in utils : 

- utils/benchmarking.py 

```
import aiohttp
import asyncio
import time

def get_public_ip(ec2, instance_id):
    response = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')
    
    if public_ip:
        return public_ip
    else:
        raise ValueError(f"No public IP address found for instance {instance_id}")

# Function to send requests to a specific endpoint
async def call_endpoint_http(session, request_num, url):
    headers = {'content-type': 'application/json'}
    try:
        async with session.get(url, headers=headers) as response:
            status_code = response.status
            response_json = await response.json()
            print(f"Request {request_num}: Status Code: {status_code}")
            print(f"Response Json {response_json}")
            return status_code, response_json
    except Exception as e:
        print(f"Request {request_num}: Failed - {str(e)}")
        return None, str(e)

# Function to benchmark the cluster
async def benchmark_cluster(cluster_url, num_requests=1000):
    start_time = time.time()
    
    async with aiohttp.ClientSession() as session:
        tasks = [call_endpoint_http(session, i, cluster_url) for i in range(num_requests)]
        await asyncio.gather(*tasks)
    
    end_time = time.time()
    total_time = end_time - start_time
    print(f"\nTotal time taken: {total_time:.2f} seconds")
    print(f"Average time per request: {total_time / num_requests:.4f} seconds")

# Main benchmark function
async def run_benchmark(lb_public_ip):
    cluster1_url = f"http://{lb_public_ip}:80/cluster1"
    cluster2_url = f"http://{lb_public_ip}:80/cluster2"
    
    print("\nBenchmarking Cluster 1")
    await benchmark_cluster(cluster1_url)
    
    print("\nBenchmarking Cluster 2")
    await benchmark_cluster(cluster2_url)
```

- utils/create_key_pair.py

```
import boto3
import os
from pathlib import Path

# Generate a key pair
def generate_key_pair(ec2_client, key_pair_name, out_path = "temp"):
    key_pair_path = Path(os.path.join(out_path, f'{key_pair_name}.pem'))
    if key_pair_path.exists():
        print(f"Key pair '{key_pair_name}' already exists.")
        return key_pair_path
    response = ec2_client.create_key_pair(KeyName=key_pair_name)

    # Save the private key to a file
    private_key = response['KeyMaterial']
    Path(out_path).mkdir(exist_ok=True)
    with open(key_pair_path, 'w') as key_file:
        key_file.write(private_key)

    print(f"Key pair '{key_pair_name}' has been created and saved to {key_pair_name}.pem")

    return key_pair_path
```

- utils/create_security_group.py :

```
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
    ec2_client.authorize_security_group_egress(
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
```

- utils/ec2_instances_launcher.py : 

```
"""Script to launch EC2 instances."""
def launch_ec2_instance(ec2, 
                    key_pair_name, 
                    security_group_id,
                    instance_type:str = "t2.micro", 
                    num_instances:int = 1, 
                    image_id:str =  "ami-0e86e20dae9224db8",
                    public_ip:bool = False,
                    user_data = "",
                    tag:tuple[str,str] = None,
                    ):
    # Create EC2 client
    # Specify instance parameters
    instance_params = {
        'ImageId': image_id, 
        'InstanceType': instance_type,
        'MinCount': num_instances,
        'MaxCount': num_instances,
        'KeyName': key_pair_name,
        'NetworkInterfaces': [{
            'AssociatePublicIpAddress': public_ip,
            'DeviceIndex': 0,
            'Groups': [security_group_id]
        }],
    }
    if tag is not None:
        instance_params["TagSpecifications"] = [
            {"ResourceType": "instance", "Tags": [{"Key": tag[0], "Value": tag[1]}]}]

    # Launch the instance
    print("Launching instances...")
    response = ec2.run_instances(UserData=user_data, **instance_params)

    # Get the instance ID
    instances_id_and_ip = []
    print("Waiting for instances to be running...")
    for instance in response['Instances']:
        instance_id = instance['InstanceId']
        if not public_ip:
            instances_id_and_ip.append((instance_id, instance["PrivateIpAddress"], None))
        else:
            instances_id_and_ip.append((instance_id, instance["PrivateIpAddress"], instance["PublicDnsName"]))

    print(f"Launched {num_instances} EC2 instances of type {instance_type} with ID and ip: {instances_id_and_ip}")

    return instances_id_and_ip
```

- utils/run_command_on_instance.py : 

```
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
```

- upload_content_to_instance.py : 

```
import os
import paramiko

def upload_files_to_instances(ec2, instance_id, key_pair_path, source_folder, out_folder = "temp"):

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
                remote_path = os.path.join(out_folder,f'{file}')
                
                # Upload the file
                sftp.put(local_path, remote_path)
            print(f"Uploaded {local_path} to {instance_id}")
        
        sftp.close()
        ssh.close()
        
    except Exception as e:
        print(f"Error uploading to instance {instance_id}: {str(e)}, {type(e)}")
```

### Folder instances_ressources :

#### Folder load_balancer : 

- bootstrap.py : 

```
LOAD_BALANCER_USER_DATA = """#!/bin/bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install python3 python3-pip -y
sudo pip3 install fastapi uvicorn requests boto3 --break-system-packages
"""

VAR_ENV = """
aws_access_key_id="{0}"
aws_secret_access_key="{1}"
aws_session_token="{2}"
"""


START_COMMAND = "python3 load_balancer.py"



def get_lb_user_data(
        aws_access_key_id, 
        aws_secret_access_key, 
        aws_session_token):
    
    temp_lb_user_data = LOAD_BALANCER_USER_DATA
    var_env_temp = VAR_ENV.format(
        aws_access_key_id, 
        aws_secret_access_key, 
        aws_session_token)
    
    main_script = var_env_temp + "\n" + open("instances_ressources/load_balancer/load_balancer.py", "r").read()

    main_script_creation = "echo '{}' > load_balancer.py".format(main_script)
    temp_lb_user_data += "\n" + main_script_creation + "\n" + START_COMMAND
    return temp_lb_user_data
```

- load_balancer.py : 

```
# Load Balancer code

from fastapi import FastAPI
import requests
import random
import boto3
import os
import uvicorn
import datetime

app = FastAPI()
#credentials
# Instances in Cluster 1 (t2.micro) and Cluster 2 (t2.large)
SWITCH_THRESHOLD = 10
GROUP_KEY = "CLUSTER"
GROUP_0_TAG = "0"
GROUP_1_TAG = "1"
cluster1_instances = []
current_id_cluster1 = 0
nb_requests_since_last_compute_cluster1 = SWITCH_THRESHOLD

cluster2_instances = []
current_id_cluster2 = 0
nb_requests_since_last_compute_cluster2 = SWITCH_THRESHOLD

response_times_cluster1 = []
response_times_cluster2 = []

def get_instances_by_tag(tag_key, tag_value):
    ec2 = boto3.client("ec2",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token = aws_session_token,
        region_name = "us-east-1"
    )
    response = ec2.describe_instances(
        Filters=[
            {
                "Name": f"tag:{tag_key}",
                "Values": [tag_value]
            },
            {
                "Name": "instance-state-name",
                "Values": ["running"]
            }
        ]
    )

    if len(response["Reservations"]) == 0:
        return []

    instances = [(res["InstanceId"], res["PrivateIpAddress"]) for res in response["Reservations"][0]["Instances"]]

    return instances

def get_response_times_instances(instances):
    response_times = []
    for instance in instances:
        response_times.append(requests.get(f"http://{instance[1]}").elapsed.total_seconds())
    return response_times

@app.get("/cluster1")
def loadbalance_cluster2():
    global current_id_cluster1
    global nb_requests_since_last_compute_cluster1
    nb_requests_since_last_compute_cluster1 +=1
    if nb_requests_since_last_compute_cluster1 >= SWITCH_THRESHOLD:
        response_times_cluster1 = get_response_times_instances(cluster1_instances)
        nb_requests_since_last_compute_cluster1 = 0
        current_id_cluster1 = response_times_cluster1.index(min(response_times_cluster1))

    selected_instance = cluster1_instances[current_id_cluster1]
    response = requests.get(f"http://{selected_instance[1]}/cluster1")
    return response.json()

@app.get("/cluster2")
def loadbalance_cluster2():
    global current_id_cluster2
    global nb_requests_since_last_compute_cluster2
    nb_requests_since_last_compute_cluster2 +=1
    if nb_requests_since_last_compute_cluster2 >= SWITCH_THRESHOLD:
        response_times_cluster2 = get_response_times_instances(cluster2_instances)
        nb_requests_since_last_compute_cluster2 = 0
        current_id_cluster2 = response_times_cluster2.index(min(response_times_cluster2))
    selected_instance = cluster2_instances[current_id_cluster2]
    response = requests.get(f"http://{selected_instance[1]}/cluster2")
    return response.json()

if __name__ == "__main__":
    cluster1_instances = get_instances_by_tag(GROUP_KEY, GROUP_0_TAG)
    cluster2_instances = get_instances_by_tag(GROUP_KEY, GROUP_1_TAG)

    # load credentials from file that should have been uploaded alongside the code
    # may need to check if key pair is necessary for sending http requests

    # Description :
    # establish map of instancei/id + private ip for both groups
    # map should contain cpu usage
    # 2 maps like this: instance_id -> {private_ip} and instance_id -> {cpu_usage}

    # either start a thread to update the cpu usage
    # or just update the cpu usage every requests

    # for each cluster request, send the request to the instance with the lowest cpu usage
    
    uvicorn.run(app, host="0.0.0.0", port=80)
```

#### Folder workers : 

- bootstrap.py : 

```
# FastAPI app content

USER_DATA = """#!/bin/bash
echo '{script}' > main.py
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install python3 python3-pip -y
sudo pip3 install fastapi uvicorn ec2-metadata --break-system-packages
uvicorn main:app --host 0.0.0.0 --port 80
"""

def get_user_data():
    
    temp_lb_user_data = USER_DATA
    main_script = open("instances_ressources/workers/listener.py", "r").read()
    temp_lb_user_data = temp_lb_user_data.format(script = main_script)
    return temp_lb_user_data
```

- listener.py : 

```
from fastapi import FastAPI
import uvicorn
import logging
import os
from ec2_metadata import ec2_metadata

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI()

# Get instance ID (you can pass this as an environment variable for each instance)
instance_id = ec2_metadata.instance_id
@app.get("/")
async def root():
    message = f"Instance {instance_id} has received the request"
    logger.info(message)
    return {"message": message}

@app.get("/cluster1")
async def cluster1():
    message = f"Cluster 1 - Instance {instance_id} is responding now!"
    logger.info(message)
    return {"message": message}

@app.get("/cluster2")
async def cluster2():
    message = f"Cluster 2 - Instance {instance_id} is responding now!"
    logger.info(message)
    return {"message": message}

if __name__ == "__main__":
    # Run the FastAPI app
    uvicorn.run(app, host="0.0.0.0", port=80)
```