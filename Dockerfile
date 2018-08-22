FROM python:3.7-rc-slim
RUN mkdir /transparentDNSproxy
WORKDIR /transparentDNSproxy
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
LABEL author="sriramsridharjob78@gmail.com" \
      version="1.0"
RUN apt-get update
RUN apt-get install -y \
    net-tools

COPY . .
CMD python dnsserver.py
