# Load Balancer From Scratch

## FastAPI deployment prcedures

Pour déployer FAstAPI, nous réalisons les étapes suivantes : 

**Mise à jour des paquets :** Pour se faire, nous avons créer un fichier bash pour faciliter la configuration des 9 VMs.

_set_up.sh_
```{bash}
sudo apt-get update && sudo apt-get upgrade -y

sudo apt-get install python3 python3-pip -y

sudo apt install python3-fastapi -y

sudo apt install python3-uvicorn -y

sudo apt install uvicorn -y

uvicorn main:app --host 0.0.0.0 --port 8000
```

**Fichier FastAPI :** Notre programme python intitulé main.py est le suivant : 

```{py}
from fastapi import FastAPI
import uvicorn
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI()

# Get instance ID (you can pass this as an environment variable for each instance)
instance_id = os.getenv("INSTANCE_ID", "Unknown Instance")

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
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

**Installation :** Pour installer tout cela, nous réalisons d'abord deux requêtes `scp`pour copier les fichiers set_up.sh et main.py. 

```
scp -i  ~/.ssh/key_montreal.pem  ./TP1/main.py ubuntu@3.235.226.168:

scp -i  ~/.ssh/key_montreal.pem  ./TP1/set_up.sh ubuntu@3.235.226.168:
```

Ensuite, nous nous connectons en ssh sur l'instance EC2 :

```
ssh -i  ~/.ssh/key_montreal.pem ubuntu@3.235.226.168
```

Une fois sur la machine, nous lançons la commande bash pour lancer toutes les commandes :

```{sh}
sh set_up.sh
```
## Cluster setup using Application Load Balancer

Pour implémenter le Load Balancing, nous allons procéder en deux étapes : 

- D'abord, nous allons créer des groupes cibles. Le premier `cluster1-micro` sur lequel on ouvre le port 80, avec comme health check `/cluster1`, dans ce groupe il y a toutes les t2.micro. 
De même, on regroupe les t2.large dans `cluster2-large` dont le health check est `/cluster2`.

- Ensuite, on implémenter le load balancer avec les règles de routage :
  - Pour les requêtes avec le chemin `/cluster1`, il y a une redirection vers `cluster1-micro`. 
  - Pour les requêtes avec le chemin `/cluster2`, il y a une redirection vers `cluster2-large`. 

## Results of your benchmark



## Instruction to run code