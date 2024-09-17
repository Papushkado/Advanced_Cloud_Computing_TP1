FROM python:3.9-buster

# Install some utilities
RUN apt-get update -y && \
    apt-get install -y build-essential libfuse-dev libcurl4-openssl-dev libxml2-dev pkg-config libssl-dev mime-support automake libtool wget tar git unzip
RUN apt-get install lsb-release -y  && apt-get install zip -y && apt-get install vim -y
RUN apt-get install -y libsndfile1

## Install AWS CLI
RUN pip3 --no-cache-dir install --upgrade awscli



WORKDIR /usr/src

RUN pip3 install --no-cache-dir --upgrade pip

COPY . .
RUN pip3 install -r requirements.txt



