# Optimized Dockerfile - Removed unnecessary packages
FROM python:3.9-slim

# Install only essential system packages
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        vim \
        curl \    
        python3 \
        python3-pip \
        python3-dev \
        tzdata \
        git \
        build-essential \
        libssl-dev \
        libffi-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Upgrade pip to latest version
RUN python -m pip install --upgrade pip

WORKDIR /opt

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Set up bashrc for container
RUN cp _bashrc_in_container /root/.bashrc

CMD ["sh", "-c", "python $FLASK_APP"] 