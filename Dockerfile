#FROM debian:bookworm
FROM python:3.9-slim

RUN apt-get update -y
RUN apt-get -y install tcpflow tcpdump python3 python3-pip python3-dev tzdata nodejs npm sudo ssh vim wget git telnet 
#RUN apt-get -y install ntp ssh vim net-tools python3 python3-pip python3-dev wget tzdata git nodejs npm sudo
#RUN apt-get -y install tcpdump tcpflow pylint iputils-ping curl unzip telnet redis lsb-release snapd
#RUN apt-get -y install mosquitto mosquitto-clients
#RUN apt-get -y install build-essential libssl-dev libffi-dev python3-setuptools python3-venv


# RUN apt-get update && apt-get install -y --no-install-recommends \
#     build-essential libpq-dev libssl-dev libffi-dev python3-dev && \
#     apt-get clean && rm -rf /var/lib/apt/lists/*


# RUN mkdir -p /opt/qlines_venv
# ENV VENV_PATH=/opt/qlines_venv
# ENV PATH="$VENV_PATH/bin:$PATH"



WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["sh", "-c", "python $FLASK_APP"] 