FROM kalilinux/kali-rolling

# Install essential security tools
RUN apt-get update && apt-get install -y \
    nmap \
    wireshark-common \
    tshark \
    tcpdump \
    masscan \
    nikto \
    dirb \
    gobuster \
    sqlmap \
    metasploit-framework \
    python3 \
    python3-pip \
    python3-scapy \
    net-tools \
    iputils-ping \
    curl \
    wget \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for integration
RUN pip3 install --break-system-packages \
    python-nmap \
    scapy \
    requests \
    asyncpg \
    redis \
    pandas \
    numpy

WORKDIR /app

# Copy security tools integration scripts
COPY . .

# Create results directory
RUN mkdir -p /app/results

# Set up non-root user for security
RUN useradd -m -s /bin/bash sectools
RUN chown -R sectools:sectools /app
USER sectools

CMD ["python3", "advanced_scanner.py"]