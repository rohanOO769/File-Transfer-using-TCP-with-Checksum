# Use an Ubuntu base image
FROM ubuntu:20.04

# Set noninteractive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build tools and OpenSSL libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory to /app and copy source files
WORKDIR /app
COPY . /app

# Compile the programs
RUN gcc -o manager_server manager_server.c -lrt -pthread
RUN gcc -o server_tcp_enc encryption/server/server_tcp_enc.c -lssl -lcrypto -pthread
RUN gcc -o client_tcp_enc encryption/client/client_tcp_enc.c -lssl -lcrypto
RUN gcc -o server_tcp_multi_enc encryption/server/server_tcp_multi_enc.c -lssl -lcrypto -pthread

# Default command: start a shell so you can run the simulation programs manually.
CMD ["/bin/bash"]
