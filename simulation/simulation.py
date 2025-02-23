# simulation/simulation.py

import time
import random
import struct
from multiprocessing import Process, shared_memory

# ------------------------------
# SharedMemoryChannel class
# ------------------------------
class SharedMemoryChannel:
    def __init__(self, name, size, create=False):
        # If creating, initialize shared memory with zeros.
        if create:
            self.shm = shared_memory.SharedMemory(name=name, create=True, size=size)
            for i in range(size):
                self.shm.buf[i] = 0
        else:
            self.shm = shared_memory.SharedMemory(name=name)
        self.size = size

    def write(self, data: bytes, delay=0.0, loss_prob=0.0, corrupt_prob=0.0):
        """
        Write data to shared memory after an optional delay.
        Optionally simulate packet loss or corruption.
        """
        time.sleep(delay)
        # Simulate packet loss.
        if random.random() < loss_prob:
            return False
        # Simulate corruption (flip first byte bit if possible).
        if random.random() < corrupt_prob and len(data) > 0:
            data = bytes([data[0] ^ 0xFF]) + data[1:]
        # Write the data, ensuring it fits into the buffer.
        n = min(len(data), self.size)
        self.shm.buf[:n] = data[:n]
        # Clear any remaining bytes.
        for i in range(n, self.size):
            self.shm.buf[i] = 0
        return True

    def read(self):
        # Return the entire buffer as bytes.
        return bytes(self.shm.buf[:self.size])

    def clear(self):
        # Zero out the shared memory.
        for i in range(self.size):
            self.shm.buf[i] = 0

    def close(self):
        self.shm.close()

    def unlink(self):
        self.shm.unlink()

# ------------------------------
# SimulatedTCP class
# ------------------------------
class SimulatedTCP:
    def __init__(self, channel: SharedMemoryChannel):
        self.channel = channel
        self.seq_num = 0

    def send(self, data: bytes):
        """
        Prepends a 4-byte sequence number to the data.
        Simulates a slight delay and a small chance of packet loss.
        """
        packet = struct.pack("!I", self.seq_num) + data
        success = self.channel.write(packet, delay=0.01, loss_prob=0.05)
        if success:
            print(f"TCP: Sent packet {self.seq_num}")
            self.seq_num += 1
        else:
            print(f"TCP: Packet {self.seq_num} lost, will retry later.")

    def receive(self):
        """
        Reads a packet from the channel. If data is present,
        parses the sequence number and the payload.
        """
        packet = self.channel.read()
        # Check if data is non-zero.
        if packet and any(b != 0 for b in packet):
            seq = struct.unpack("!I", packet[:4])[0]
            data = packet[4:]
            print(f"TCP: Received packet {seq}: {data.decode(errors='ignore')}")
            self.channel.clear()
            return seq, data
        return None, None

# ------------------------------
# SimulatedUDP class
# ------------------------------
class SimulatedUDP:
    def __init__(self, channel: SharedMemoryChannel):
        self.channel = channel

    def send(self, data: bytes):
        """
        Sends data without a sequence number. Uses a shorter delay
        and a higher chance of packet loss.
        """
        success = self.channel.write(data, delay=0.005, loss_prob=0.1)
        if success:
            print("UDP: Sent packet")
        else:
            print("UDP: Packet lost")

    def receive(self):
        data = self.channel.read()
        if data and any(b != 0 for b in data):
            print("UDP: Received packet:", data.decode(errors='ignore'))
            self.channel.clear()
            return data
        return None

# ------------------------------
# Client process function
# ------------------------------
def client_process(client_id, protocol='TCP'):
    shm_name = f"channel_{client_id}"
    size = 1024
    # Attach to an existing shared memory channel.
    try:
        channel = SharedMemoryChannel(name=shm_name, size=size, create=False)
    except FileNotFoundError:
        # If not found, create one (in case the server hasn't yet created it).
        channel = SharedMemoryChannel(name=shm_name, size=size, create=True)
    if protocol.upper() == 'TCP':
        endpoint = SimulatedTCP(channel)
    else:
        endpoint = SimulatedUDP(channel)

    # Send a few messages.
    for i in range(5):
        message = f"Message {i} from client {client_id}"
        if protocol.upper() == 'TCP':
            endpoint.send(message.encode())
        else:
            endpoint.send(message.encode())
        time.sleep(0.1)
    channel.close()

# ------------------------------
# Server process function
# ------------------------------
def server_process(client_ids):
    size = 1024
    # Create (or re-create) shared memory channels for each client.
    channels = {}
    for cid in client_ids:
        shm_name = f"channel_{cid}"
        channels[cid] = SharedMemoryChannel(name=shm_name, size=size, create=True)

    try:
        # Server loop: periodically poll each channel.
        for _ in range(20):
            for cid, channel in channels.items():
                data = channel.read()
                if data and any(b != 0 for b in data):
                    # For TCP messages, first 4 bytes represent the sequence number.
                    # For UDP messages, assume the first 4 bytes are zero.
                    if data[:4] != b'\x00\x00\x00\x00':
                        seq = struct.unpack("!I", data[:4])[0]
                        msg = data[4:]
                        print(f"Server received from client {cid} (TCP packet {seq}): {msg.decode(errors='ignore')}")
                    else:
                        print(f"Server received from client {cid} (UDP): {data.decode(errors='ignore')}")
                    channel.clear()
            time.sleep(0.05)
    finally:
        # Clean up shared memory.
        for cid, channel in channels.items():
            channel.close()
            channel.unlink()

# ------------------------------
# Main function to start server and clients
# ------------------------------
if __name__ == "__main__":
    # Define client IDs for TCP and UDP clients.
    tcp_client_ids = [1, 2, 3]
    udp_client_ids = [101, 102, 103]
    all_client_ids = tcp_client_ids + udp_client_ids

    # Start the server process.
    server = Process(target=server_process, args=(all_client_ids,))
    server.start()

    # Give the server a moment to set up shared memory channels.
    time.sleep(0.5)

    # Start all client processes.
    clients = []
    for cid in tcp_client_ids:
        p = Process(target=client_process, args=(cid, 'TCP'))
        clients.append(p)
    for cid in udp_client_ids:
        p = Process(target=client_process, args=(cid, 'UDP'))
        clients.append(p)

    for p in clients:
        p.start()

    for p in clients:
        p.join()

    server.join()
