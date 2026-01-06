FROM ubuntu:20.04

# Install vulnerable services for testing (DVWA-like environment)
RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    php-mysql \
    mysql-server \
    openssh-server \
    vsftpd \
    telnetd \
    netcat \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir /var/run/sshd
RUN echo 'root:vulnerable123' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Create vulnerable web application
RUN mkdir -p /var/www/html/vulnerable
COPY vulnerable_app/ /var/www/html/vulnerable/

# Create test users
RUN useradd -m -s /bin/bash testuser
RUN echo 'testuser:password123' | chpasswd

# Expose vulnerable services
EXPOSE 22 23 21 80 3306 8080

# Start services script
COPY start_services.sh /start_services.sh
RUN chmod +x /start_services.sh

CMD ["/start_services.sh"]