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
SWITCH_THRESHOLD = 0.50
GROUP_KEY = "CLUSTER"
GROUP_0_TAG = "0"
GROUP_1_TAG = "1"
cluster1_instances = []
current_id_cluster1 = 0
cluster2_instances = []
current_id_cluster2 = 0
cpu_loads = {}


cloudwatch = boto3.client("cloudwatch",
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    aws_session_token=aws_session_token,
    region_name="us-east-1"
)

def get_cpu_load(instance_id):
    response = cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=3600),
        EndTime=datetime.datetime.now(datetime.timezone.utc),
        Period=10,
        Statistics=["Average"],
    )
    if len(response["Datapoints"]) > 0:
        return response["Datapoints"][-1]["Average"]
    else:
        return 0.0

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

    instances = [(res["Instances"][0]["InstanceId"], res["Instances"][0]["PrivateIpAddress"]) for res in response["Reservations"]]

    return instances

@app.get("/cluster1")
def loadbalance_cluster2():
    global current_id_cluster1
    cpu_load = get_cpu_load(cluster1_instances[current_id_cluster1][0])
    if cpu_load > SWITCH_THRESHOLD:
        current_id_cluster1 = (current_id_cluster1 + 1) % len(cluster1_instances)
    selected_instance = cluster1_instances[current_id_cluster1]
    response = requests.get(f"http://{selected_instance[1]}/cluster1")
    return response.json()

@app.get("/cluster2")
def loadbalance_cluster2():
    global current_id_cluster2
    cpu_load = get_cpu_load(cluster2_instances[current_id_cluster2][0])
    if cpu_load > SWITCH_THRESHOLD:
        current_id_cluster2 = (current_id_cluster2 + 1) % len(cluster2_instances)
    selected_instance = cluster2_instances[current_id_cluster2]
    response = requests.get(f"http://{selected_instance[1]}/cluster2")
    return response.json()

if __name__ == "__main__":
    cluster1_instances = get_instances_by_tag(GROUP_KEY, GROUP_0_TAG)

    cluster2_instances = get_instances_by_tag(GROUP_KEY, GROUP_1_TAG)

    #load credentials from file that should have been uploaded alonside the code
    # may need to check if key pair is necessary for sending http requests

    #todo establish map of instancei/id + private ip for both groups
    #   map should contain cpu usage
    #  2 maps like this: instance_id -> {private_ip} and instance_id -> {cpu_usage}

    #either start a thread to update the cpu usage
    #or just update the cpu usage every requests

    #for each cluster request, send the request to the instance with the lowest cpu usage
    uvicorn.run(app, host="0.0.0.0", port=80)
