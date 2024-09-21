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