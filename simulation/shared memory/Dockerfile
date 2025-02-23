# Use an Ubuntu base image
FROM ubuntu:20.04

# Set noninteractive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build tools
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy the simulation source files into /app
WORKDIR /app
COPY . /app

# Compile the programs
RUN gcc -o init_shm init_shm.c -lrt -pthread
RUN gcc -o manager_server manager_server.c -lrt -pthread
RUN gcc -o server server.c -lrt -pthread
RUN gcc -o client client.c -lrt -pthread

# Default command is to run a shell so you can run the simulation programs manually.
CMD ["/bin/bash"]
