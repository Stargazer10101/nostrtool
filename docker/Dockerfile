# Dockerfile

# Pull base image
FROM python:3.9-bullseye

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update -y && apt upgrade -y && apt dist-upgrade -y && apt autoremove -y

# Install additional required tools
RUN apt install -y wget curl git nano python3-virtualenv

# Set work directory
WORKDIR /code

# Copy bashrc
COPY docker/bashrc /root/.bashrc

# Create virtualenv
RUN virtualenv -p /usr/bin/python3.9 /srv/.env

# Set up the project directory
WORKDIR /srv/nostrtool

# Copy local repository files
COPY . .

# Clone python-nostr dependency
RUN git clone https://github.com/kdmukai/python-nostr.git
WORKDIR /srv/nostrtool/python-nostr
RUN git checkout dev

# Install dependencies
WORKDIR /srv/nostrtool
RUN sed -i '/Flask==2.2.2/a Werkzeug==2.2.3' requirements.txt
RUN echo "git+https://github.com/kdmukai/python-nostr.git@dev" >> requirements.txt
RUN /srv/.env/bin/pip install -r requirements.txt --no-cache-dir

# Set work directory
WORKDIR /srv/nostrtool

# Remove any existing .app_secret directory and create the secret key file
RUN rm -rf .app_secret
RUN echo "Current directory:" && pwd
RUN /srv/.env/bin/python --version
RUN /srv/.env/bin/python -c 'import secrets; print(secrets.token_hex())' > .app_secret || { echo "Failed to create .app_secret"; exit 1; }
RUN ls -la /srv/nostrtool/.app_secret || { echo "File not found"; exit 1; }
RUN cat /srv/nostrtool/.app_secret
RUN chmod 644 .app_secret
