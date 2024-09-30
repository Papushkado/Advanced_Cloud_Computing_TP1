This code can be ran using docker

First, make sure you have docker installed on your machine.

Then, run the following command in the root directory of the project:
```bash
docker build -t log8751e-tp1 .
```
Then, run the following command to start the container:
```bash
docker run -it log8751e-tp1 bash
```

If you are not using docker, make sure to install the requirements.txt file. You can do this by running the following command:
```bash
pip install -r requirements.txt
```

Then, you must setup your credentials. This can be done by either setting the environment variables or by creating a .env file in the root directory of the project/container running.

This will start a container with the project installed. You can then run the following command to start the server:
```bash
python main.py
```
The code will then launch the machines and after a delay run the benchmarks.
These benchmarks will be logged into benchmark_log.txt.
Then, after a another delay, the code will terminate the machines and cleanup any ressources.