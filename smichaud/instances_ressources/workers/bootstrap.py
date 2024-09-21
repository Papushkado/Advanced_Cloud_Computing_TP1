# FastAPI app content

USER_DATA = """#!/bin/bash
echo '{script}' > main.py
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install python3 python3-pip -y
sudo pip3 install fastapi uvicorn --break-system-packages
uvicorn main:app --host 0.0.0.0 --port 80
"""

def get_user_data():
    
    temp_lb_user_data = USER_DATA
    main_script = open("instances_ressources/workers/listener.py", "r").read()
    temp_lb_user_data = temp_lb_user_data.format(script = main_script)
    return temp_lb_user_data