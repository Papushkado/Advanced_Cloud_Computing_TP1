# FastAPI Benchmark and Deployment Report

---
- [FastAPI Benchmark and Deployment Report](#fastapi-benchmark-and-deployment-report)
  - [FastAPI Deployment Procedure](#fastapi-deployment-procedure)
    - [Key Pair and Security Group](#key-pair-and-security-group)
    - [Worker Instances Setup](#worker-instances-setup)
    - [Load Balancer Deployment](#load-balancer-deployment)
  - [Cluster Setup Using Application Load Balancer](#cluster-setup-using-application-load-balancer)
    - [Tagging and Instance Management](#tagging-and-instance-management)
    - [Expectations](#expectations)
  - [Benchmark Results](#benchmark-results)
  - [Instructions to Run code](#instructions-to-run-code)
    - [Prerequisites](#prerequisites)
  - [EC2 Instance Creation](#ec2-instance-creation)
    - [Deploy FastAPI](#deploy-fastapi)
    - [Test tke Load Balancer](#test-tke-load-balancer)
  - [Conclusion](#conclusion)
  - [Appendix](#appendix)
    - [Code](#code)
      - [main.py :](#mainpy-)
      - [Folder utils :](#folder-utils-)
      - [Folder instances\_ressources :](#folder-instances_ressources-)
        - [Folder load\_balancer :](#folder-load_balancer-)
        - [Folder workers :](#folder-workers-)
    - [Logs of the benchmark :](#logs-of-the-benchmark-)

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

_Remark :_ The responnsiveness is calculated after a fix number of requests sent. (10 on each cluster in [Folder load\_balancer :](#folder-load_balancer-) in load_balancer.py)

## Cluster Setup Using Application Load Balancer

We deployed two clusters:

- **Cluster 1:** Instances of type t2.micro.
- **Cluster 2:** Instances of type t2.large.

Each cluster was tagged accordingly, allowing the load balancer to differentiate between them. The load balancer was configured to route traffic between these clusters based on the time response of instances. The fastest to answer will have the request.

### Tagging and Instance Management

Each instance was tagged as part of either Cluster 0 or Cluster 1. The load balancer uses these tags to direct traffic, ensuring that requests are handled efficiently. The custom logic for this was written in Python and deployed on an EC2 instance running the load balancer.

### Expectations

Before any experiment, we expect that the t2.micro cluster to have higher response time than the t2.large. It is to note however that the workload is not expensive, so the difference in response time might not be significant.
Indeed, the capacity of the virtual machines entail different behaviors regarding the amount of requests. 

## Benchmark Results 

The raw results of the benchmark are the following : 
- Cluster 1 (t2.micro) : 
```
Total time taken: 6.75 seconds
Average time per request: 0.0067 seconds
```
- Cluster 2 (t2.large) : 
```
Total time taken: 5.87 seconds
Average time per request: 0.0059 seconds
```

We conclude that t2.large clusters are 14% more efficient than t2.micro clusters. 
However we expected that cluster 1 lost some requests due to too much requests sended in opposite of cluster 2 who would easily respond to those requests. 


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

### Code 

All the code is available in [Github](https://github.com/Papushkado/Advanced_Cloud_Computing_TP1).

#### main.py :

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
#### Folder utils :
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

#### Folder instances_ressources :

##### Folder load_balancer : 

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

##### Folder workers : 

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

### Logs of the benchmark : 

```
ASIAZCUISHQHHJQLA2OD
Load Balancer Public IP: 3.89.196.172

Benchmarking Cluster 1
Request 1: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 2: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 4: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 0: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 3: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 5: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 12: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 9: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 6: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 13: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 35: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 24: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 11: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 29: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 7: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 19: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 14: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 31: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 21: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 18: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 10: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 34: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 15: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 27: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 46: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 39: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 16: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 17: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 28: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 26: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 30: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 8: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 33: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 49: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 41: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 25: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 20: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 22: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 42: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 23: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 48: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 43: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 52: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 32: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 50: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 45: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 54: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 75: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 59: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 55: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 61: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 36: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 80: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 47: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 82: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 72: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 67: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 62: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 60: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 57: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 53: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 63: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 81: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 38: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 56: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 44: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 84: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 71: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 78: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 76: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 40: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 85: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 64: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 68: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 79: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 69: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 77: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 74: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 65: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 89: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 73: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 51: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 37: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 66: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 58: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 70: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 83: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 118: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 98: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 95: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 92: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 96: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 111: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 87: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 106: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 117: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 105: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 116: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 113: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 103: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 119: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 93: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 101: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 123: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 100: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 94: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 115: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 114: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 104: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 121: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 122: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 110: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 90: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 126: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 107: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 108: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 91: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 86: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 124: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 112: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 97: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 88: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 120: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 109: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 99: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 125: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 102: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 130: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 127: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 128: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 129: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 131: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 132: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 134: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 136: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 147: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 154: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 138: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 161: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 144: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 140: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 142: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 150: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 155: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 146: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 160: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 143: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 179: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 168: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 139: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 141: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 178: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 156: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 153: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 159: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 149: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 157: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 151: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 164: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 180: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 158: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 166: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 145: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 170: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 148: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 162: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 169: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 172: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 152: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 165: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 137: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 171: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 163: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 167: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 173: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 135: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 174: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 133: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 177: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 176: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 181: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 185: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 182: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 186: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 183: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 175: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 184: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 190: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 195: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 192: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 188: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 213: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 209: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 206: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 212: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 200: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 219: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 202: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 214: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 215: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 194: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 217: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 218: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 216: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 199: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 207: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 201: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 197: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 203: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 196: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 198: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 189: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 187: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 205: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 208: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 193: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 191: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 211: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 204: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 220: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 221: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 224: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 223: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 222: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 226: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 210: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 225: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 228: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 227: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 237: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 229: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 241: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 230: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 244: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 235: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 233: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 246: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 242: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 251: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 248: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 236: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 265: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 239: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 240: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 260: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 252: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 234: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 255: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 243: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 231: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 238: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 245: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 264: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 263: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 250: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 247: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 232: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 259: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 257: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 249: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 266: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 254: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 261: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 258: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 253: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 256: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 268: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 262: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 267: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 271: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 269: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 276: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 273: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 274: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 275: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 270: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 309: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 295: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 285: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 281: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 297: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 277: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 291: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 286: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 290: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 303: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 279: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 293: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 292: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 299: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 296: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 289: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 278: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 304: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 288: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 298: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 302: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 294: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 301: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 280: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 283: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 284: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 300: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 272: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 305: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 306: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 287: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 307: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 282: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 311: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 313: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 310: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 312: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 314: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 315: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 308: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 333: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 332: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 317: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 338: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 319: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 352: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 323: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 325: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 344: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 322: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 349: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 353: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 354: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 331: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 350: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 351: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 355: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 324: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 341: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 336: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 340: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 329: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 330: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 318: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 339: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 335: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 328: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 321: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 346: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 342: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 334: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 327: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 345: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 316: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 347: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 320: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 337: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 348: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 326: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 343: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 357: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 356: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 358: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 359: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 367: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 368: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 371: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 370: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 364: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 390: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 365: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 384: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 399: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 393: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 386: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 398: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 378: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 375: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 376: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 373: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 397: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 362: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 372: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 363: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 385: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 395: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 381: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 360: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 366: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 369: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 396: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 392: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 374: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 361: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 377: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 380: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 382: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 383: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 391: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 394: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 379: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 387: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 389: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 388: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 400: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 402: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 404: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 403: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 401: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 406: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 407: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 423: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 431: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 433: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 448: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 446: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 412: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 408: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 447: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 417: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 430: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 444: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 436: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 414: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 425: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 415: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 420: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 426: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 411: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 443: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 428: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 442: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 445: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 438: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 429: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 418: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 437: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 449: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 416: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 410: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 421: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 422: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 439: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 434: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 435: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 427: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 424: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 441: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 405: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 409: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 419: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 440: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 413: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 432: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 453: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 460: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 452: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 459: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 450: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 455: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 451: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 458: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 464: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 457: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 456: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 454: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 475: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 473: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 485: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 465: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 468: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 467: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 463: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 461: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 477: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 472: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 484: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 487: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 470: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 488: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 469: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 476: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 483: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 466: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 481: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 462: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 479: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 480: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 478: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 486: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 474: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 471: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 489: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 495: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 497: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 490: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 496: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 493: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 494: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 482: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 492: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 519: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 526: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 491: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 522: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 498: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 511: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 503: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 515: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 502: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 513: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 528: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 529: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 499: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 501: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 527: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 530: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 514: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 525: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 510: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 517: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 505: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 509: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 518: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 512: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 506: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 508: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 507: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 520: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 516: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 523: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 500: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 504: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 521: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 524: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 534: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 533: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 535: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 531: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 536: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 532: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 537: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 541: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 543: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 568: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 539: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 574: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 544: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 570: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 569: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 575: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 567: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 546: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 542: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 576: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 573: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 577: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 572: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 561: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 578: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 558: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 571: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 563: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 549: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 566: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 556: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 579: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 540: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 551: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 565: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 548: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 547: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 564: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 562: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 554: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 560: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 555: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 553: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 538: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 550: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 557: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 545: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 559: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 552: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 589: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 591: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 586: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 606: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 605: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 599: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 580: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 600: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 588: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 584: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 593: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 618: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 582: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 619: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 597: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 617: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 595: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 590: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 585: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 603: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 609: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 610: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 587: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 598: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 601: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 607: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 602: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 612: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 611: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 592: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 613: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 583: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 615: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 594: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 604: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 614: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 596: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 608: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 616: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 581: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 621: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 628: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 624: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 627: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 625: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 623: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 620: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 622: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 626: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 660: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 631: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 659: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 629: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 632: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 641: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 654: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 648: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 669: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 666: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 667: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 664: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 662: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 663: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 645: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 665: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 634: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 646: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 657: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 661: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 644: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 655: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 636: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 638: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 637: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 643: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 651: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 635: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 633: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 640: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 639: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 658: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 656: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 630: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 650: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 647: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 652: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 653: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 649: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 642: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 671: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 668: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 670: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 672: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 676: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 674: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 675: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 673: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 677: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 679: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 687: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 682: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 681: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 708: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 716: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 702: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 690: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 683: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 694: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 711: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 691: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 706: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 699: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 686: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 695: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 712: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 680: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 689: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 715: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 697: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 692: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 701: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 684: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 685: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 703: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 698: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 709: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 713: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 714: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 688: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 678: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 718: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 704: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 710: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 700: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 696: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 693: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 705: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 707: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 717: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 719: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 720: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 727: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 721: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 726: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 722: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 723: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 724: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 731: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 725: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 740: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 735: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 759: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 762: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 766: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 732: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 734: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 764: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 730: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 755: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 749: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 750: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 729: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 763: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 742: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 728: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 754: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 758: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 751: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 747: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 737: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 760: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 756: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 744: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 745: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 757: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 739: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 736: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 738: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 746: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 753: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 761: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 748: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 752: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 743: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 733: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 767: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 741: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 765: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 780: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 788: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 769: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 774: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 775: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 771: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 777: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 768: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 811: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 810: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 802: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 787: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 772: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 776: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 785: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 803: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 773: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 809: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 790: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 778: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 791: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 782: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 789: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 805: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 799: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 783: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 806: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 784: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 779: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 786: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 796: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 770: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 781: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 793: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 797: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 813: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 800: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 812: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 792: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 794: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 817: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 801: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 795: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 816: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 804: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 798: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 807: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 814: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 808: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 815: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 843: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 830: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 848: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 822: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 838: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 820: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 837: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 847: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 819: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 825: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 844: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 828: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 851: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 827: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 856: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 829: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 835: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 853: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 836: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 854: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 852: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 846: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 818: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 850: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 849: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 834: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 826: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 824: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 833: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 831: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 823: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 821: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 842: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 839: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 845: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 841: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 832: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 857: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 855: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 862: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 840: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 863: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 865: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 861: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 860: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 859: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 858: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 871: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 873: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 864: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 875: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 897: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 901: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 870: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 898: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 904: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 876: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 900: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 902: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 877: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 881: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 895: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 866: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 888: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 899: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 894: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 886: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 872: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 882: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 896: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 880: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 884: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 885: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 892: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 890: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 887: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 874: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 879: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 867: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 869: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 889: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 868: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 883: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 891: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 893: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 878: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 903: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 906: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 907: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 905: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 932: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 908: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 909: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 918: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 913: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 924: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 936: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 933: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 912: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 911: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 915: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 914: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 917: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 927: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 919: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 937: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 934: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 922: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 916: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 944: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 945: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 930: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 947: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 946: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 910: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 943: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 928: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 938: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 923: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 921: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 940: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 931: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 935: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 920: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 941: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 926: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 942: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 929: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 949: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 925: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 948: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 939: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 951: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 952: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 958: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 955: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 962: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 954: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 960: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 994: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 990: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 991: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 992: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 996: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 963: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 961: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 959: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 956: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 984: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 974: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 953: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 993: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 975: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 978: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 950: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 968: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 957: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-07954f2235d03ed44 is responding now!'}
Request 965: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 971: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 979: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 973: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 980: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 977: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 964: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 967: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}
Request 987: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 986: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 966: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 983: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 982: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 988: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 970: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 981: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 969: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 989: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 985: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 976: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0c892f86301affb95 is responding now!'}
Request 999: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 972: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 997: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 998: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0d8a23d535618cd2b is responding now!'}
Request 995: Status Code: 200
Response Json {'message': 'Cluster 1 - Instance i-0960565d09f58ada8 is responding now!'}

Total time taken: 6.75 seconds
Average time per request: 0.0067 seconds

Benchmarking Cluster 2
Request 0: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 6: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 3: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 4: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 9: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 14: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 16: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 7: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 19: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 5: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 21: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 20: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 8: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 2: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 32: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 45: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 61: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 30: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 35: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 42: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 44: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 46: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 47: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 43: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 38: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 40: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 33: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 17: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 23: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 1: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 36: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 31: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 29: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 25: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 52: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 28: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 15: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 12: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 18: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 41: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 22: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 13: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 26: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 10: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 37: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 48: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 11: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 54: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 50: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 56: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 58: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 51: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 27: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 63: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 34: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 39: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 24: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 49: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 64: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 85: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 72: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 67: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 65: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 75: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 76: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 80: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 55: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 96: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 90: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 78: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 60: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 53: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 97: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 77: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 79: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 93: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 71: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 81: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 62: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 74: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 92: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 59: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 91: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 66: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 95: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 88: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 69: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 84: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 94: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 89: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 86: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 73: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 83: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 68: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 57: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 70: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 87: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 82: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 105: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 99: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 98: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 104: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 106: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 100: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 102: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 101: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 103: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 107: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 131: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 117: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 138: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 113: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 125: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 112: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 128: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 111: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 110: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 126: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 137: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 108: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 134: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 141: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 140: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 130: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 109: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 115: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 123: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 129: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 144: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 133: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 120: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 143: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 145: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 135: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 119: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 124: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 142: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 136: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 132: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 116: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 139: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 118: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 146: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 127: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 121: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 114: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 122: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 147: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 151: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 153: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 149: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 150: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 148: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 152: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 155: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 159: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 162: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 183: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 184: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 163: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 176: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 185: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 167: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 160: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 170: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 175: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 178: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 154: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 182: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 166: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 171: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 156: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 173: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 169: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 174: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 165: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 157: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 164: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 181: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 168: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 161: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 179: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 172: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 180: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 158: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 188: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 189: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 194: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 177: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 190: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 191: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 186: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 192: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 187: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 195: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 193: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 222: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 223: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 218: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 220: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 226: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 197: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 221: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 228: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 217: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 199: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 229: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 225: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 198: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 216: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 210: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 224: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 196: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 206: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 209: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 205: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 208: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 207: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 203: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 211: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 213: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 204: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 215: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 227: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 200: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 219: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 235: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 230: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 212: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 231: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 232: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 201: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 236: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 214: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 202: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 246: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 241: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 248: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 239: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 243: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 237: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 242: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 247: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 252: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 244: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 260: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 261: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 257: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 255: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 234: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 259: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 251: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 256: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 274: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 245: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 249: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 258: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 263: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 270: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 254: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 269: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 233: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 265: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 262: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 250: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 271: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 253: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 264: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 266: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 238: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 240: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 273: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 268: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 272: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 267: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 276: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 275: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 277: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 280: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 278: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 282: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 279: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 284: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 297: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 322: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 281: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 302: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 306: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 303: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 315: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 295: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 308: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 283: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 310: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 285: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 323: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 291: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 325: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 324: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 326: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 304: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 321: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 290: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 313: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 293: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 289: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 314: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 307: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 317: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 288: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 287: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 294: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 300: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 320: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 305: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 298: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 299: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 301: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 311: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 286: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 296: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 319: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 318: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 309: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 316: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 312: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 292: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 329: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 339: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 333: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 328: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 330: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 334: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 331: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 337: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 335: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 356: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 349: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 343: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 327: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 351: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 361: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 352: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 345: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 332: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 358: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 340: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 342: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 348: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 341: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 353: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 355: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 369: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 336: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 338: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 344: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 359: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 367: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 357: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 354: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 350: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 368: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 347: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 365: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 371: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 362: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 364: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 360: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 370: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 346: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 366: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 372: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 363: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 375: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 373: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 374: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 377: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 385: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 407: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 383: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 397: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 381: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 382: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 376: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 412: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 404: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 386: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 393: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 411: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 401: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 415: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 408: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 378: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 409: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 399: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 394: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 391: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 413: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 417: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 388: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 392: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 402: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 405: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 390: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 400: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 403: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 379: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 398: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 380: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 410: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 389: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 406: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 387: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 395: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 384: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 396: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 420: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 421: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 419: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 416: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 418: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 414: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 422: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 430: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 432: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 423: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 456: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 431: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 425: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 424: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 436: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 426: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 457: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 428: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 462: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 455: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 461: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 441: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 459: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 453: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 434: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 438: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 445: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 427: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 442: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 437: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 443: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 448: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 458: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 439: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 440: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 450: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 452: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 451: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 464: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 447: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 429: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 433: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 454: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 446: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 435: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 449: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 444: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 465: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 463: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 460: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 480: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 482: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 469: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 472: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 474: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 484: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 504: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 483: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 494: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 473: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 478: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 467: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 498: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 486: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 477: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 479: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 468: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 481: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 489: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 500: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 470: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 487: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 466: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 503: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 506: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 471: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 475: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 495: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 476: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 490: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 491: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 485: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 502: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 493: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 492: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 497: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 496: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 501: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 488: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 505: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 507: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 499: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 511: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 510: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 508: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 509: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 519: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 514: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 520: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 517: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 525: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 518: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 512: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 536: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 515: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 516: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 539: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 541: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 535: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 532: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 537: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 543: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 522: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 538: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 551: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 530: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 540: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 544: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 545: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 529: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 542: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 524: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 548: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 526: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 546: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 547: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 554: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 523: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 552: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 527: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 531: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 534: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 513: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 533: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 521: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 528: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 561: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 555: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 553: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 549: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 556: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 558: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 557: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 559: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 550: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 591: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 560: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 571: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 590: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 585: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 572: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 577: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 579: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 568: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 584: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 581: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 566: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 565: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 587: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 569: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 586: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 570: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 574: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 567: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 580: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 573: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 578: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 583: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 562: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 575: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 576: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 563: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 589: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 598: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 588: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 600: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 597: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 593: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 599: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 564: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 594: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 596: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 592: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 582: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 595: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 626: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 601: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 603: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 613: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 630: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 614: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 608: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 639: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 612: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 631: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 618: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 636: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 611: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 635: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 638: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 642: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 604: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 633: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 617: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 637: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 622: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 605: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 602: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 634: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 632: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 621: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 606: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 624: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 610: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 607: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 615: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 623: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 619: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 609: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 620: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 616: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 627: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 625: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 629: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 628: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 659: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 672: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 641: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 660: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 661: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 657: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 640: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 673: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 674: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 676: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 644: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 663: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 680: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 675: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 679: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 677: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 667: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 654: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 681: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 651: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 643: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 665: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 653: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 652: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 647: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 669: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 646: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 668: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 670: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 650: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 666: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 664: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 656: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 671: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 648: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 655: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 645: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 649: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 658: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 662: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 683: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 687: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 685: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 689: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 678: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 686: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 682: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 684: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 688: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 711: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 694: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 699: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 700: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 704: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 707: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 701: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 702: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 706: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 697: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 703: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 712: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 717: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 705: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 715: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 695: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 710: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 690: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 714: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 692: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 691: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 713: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 696: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 693: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 716: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 725: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 698: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 720: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 709: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 723: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 729: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 721: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 726: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 718: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 708: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 728: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 719: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 722: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 727: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 724: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 734: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 731: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 758: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 745: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 743: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 757: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 755: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 754: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 753: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 774: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 762: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 751: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 773: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 737: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 750: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 752: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 732: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 744: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 748: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 759: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 760: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 763: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 740: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 756: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 761: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 742: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 735: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 738: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 746: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 747: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 733: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 739: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 730: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 749: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 741: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 736: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 764: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 767: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 766: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 768: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 802: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 765: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 777: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 770: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 788: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 778: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 801: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 782: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 781: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 769: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 797: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 796: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 798: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 772: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 789: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 775: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 793: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 771: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 776: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 786: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 783: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 799: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 795: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 800: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 779: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 791: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 792: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 805: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 785: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 780: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 787: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 794: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 815: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 811: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 790: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 814: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 817: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 784: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 810: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 803: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 804: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 807: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 809: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 808: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 806: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 812: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 820: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 821: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 823: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 822: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 813: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 818: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 816: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 824: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 828: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 859: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 833: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 849: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 844: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 854: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 848: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 850: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 843: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 845: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 846: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 825: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 855: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 851: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 834: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 827: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 829: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 847: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 832: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 830: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 819: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 826: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 861: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 835: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 863: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 842: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 856: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 862: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 852: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 860: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 858: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 831: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 857: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 853: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 840: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 837: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 841: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 839: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 836: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 838: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 898: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 892: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 871: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 899: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 887: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 896: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 864: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 888: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 882: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 902: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 872: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 866: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 889: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 869: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 874: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 886: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 873: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 870: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 868: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 884: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 879: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 878: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 891: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 901: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 885: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 865: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 894: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 890: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 876: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 897: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 900: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 881: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 877: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 893: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 895: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 867: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 880: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 883: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 875: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 904: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 903: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 912: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 908: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 913: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 906: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 910: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 905: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 907: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 914: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 911: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 909: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 927: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 932: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 935: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 928: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 920: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 917: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 924: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 925: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 926: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 922: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 934: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 916: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 937: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 919: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 938: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 930: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 933: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 921: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 942: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 952: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 949: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 940: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 918: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 947: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 929: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 946: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 945: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 923: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 941: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 915: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 944: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 950: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 948: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 943: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 939: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 936: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 931: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 955: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 957: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 958: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 951: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 960: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 959: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 956: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 953: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 954: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 994: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 993: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 986: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 992: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 961: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 977: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 963: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 998: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 976: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 975: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 990: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 999: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 966: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 985: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 991: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 974: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 996: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 983: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 978: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 982: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 995: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 962: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 980: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 984: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 968: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 997: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 973: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 965: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 988: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 970: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 964: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 989: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 987: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-032a09b145765bea9 is responding now!'}
Request 972: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 981: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-072868d3c9a244cdf is responding now!'}
Request 979: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-0f05fd0b136f134be is responding now!'}
Request 971: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 967: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}
Request 969: Status Code: 200
Response Json {'message': 'Cluster 2 - Instance i-03ad573fe462b8bb9 is responding now!'}

Total time taken: 5.87 seconds
Average time per request: 0.0059 seconds
```