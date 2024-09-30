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