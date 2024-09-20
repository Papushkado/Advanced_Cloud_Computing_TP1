

LOAD_BALANCER_USER_DATA = f"""#!/bin/bash
EXPORT AWS_ACCESS_KEY_ID={0}
EXPORT AWS_SECRET_ACCESS_KEY={1}
EXPORT AWS_SESSION_TOKEN={2}
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install python3 python3-pip -y
sudo pip3 install fastapi uvicorn requests boto3 --break-system-packages
"""

START_COMMAND = "uvicorn load_balancer:app --host 0.0.0.0 --port 8000"