FROM debian:10-slim

RUN apt update && \
    apt install -y locales dpkg && \
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    apt install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev curl libbz2-dev python3 python3-venv python3-pip

RUN apt install -y wget unzip

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

RUN mkdir -p /opt/inspector
WORKDIR /opt/inspector

COPY . /opt/inspector

RUN pip3 install --no-cache-dir -r requirements.txt
RUN pip3 install file_read_backwards

EXPOSE 5000

CMD ["python3", "/opt/inspector/app.py"]