# simulation/client_sim.py

import socket, struct, hashlib, sys, os, time

# --- Helper functions ---
def send_msg(sock, data: bytes, addr=None, udp=False):
    """Send a message with a 4-byte length prefix."""
    msg_length = struct.pack("!I", len(data))
    if udp:
        sock.sendto(msg_length + data, addr)
    else:
        sock.sendall(msg_length + data)

def recvall(sock, n):
    """Helper to receive exactly n bytes (TCP only)."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_msg(sock, udp=False):
    """Receive a message with a 4-byte length prefix.
       For UDP, returns (data, addr)."""
    if not udp:
        raw_msglen = recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack("!I", raw_msglen)[0]
        return recvall(sock, msglen)
    else:
        data, addr = sock.recvfrom(65535)
        if len(data) < 4:
            return None, addr
        msglen = struct.unpack("!I", data[:4])[0]
        return data[4:], addr

# --- TCP Client ---
def tcp_client(file_path, server_host, server_port):
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return
    with open(file_path, "rb") as f:
        file_data = f.read()
    print(f"Read file {file_path} ({len(file_data)} bytes).")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_host, server_port))
    # Send the file.
    send_msg(sock, file_data)
    print("File sent to TCP server.")
    # Receive header.
    header_msg = recv_msg(sock)
    if header_msg is None:
        print("No header received.")
        return
    total_chunks = struct.unpack("!I", header_msg[:4])[0]
    expected_file_checksum = header_msg[4:68].decode()
    print(f"Expecting {total_chunks} chunks with file checksum {expected_file_checksum}")
    received_chunks = {}
    sock.settimeout(2)
    # Receive initial chunks.
    while True:
        try:
            chunk_msg = recv_msg(sock)
            if chunk_msg is None:
                break
            if len(chunk_msg) < 36:
                continue
            seq = struct.unpack("!I", chunk_msg[:4])[0]
            expected_chunk_hash = chunk_msg[4:36]
            chunk_data = chunk_msg[36:]
            actual_chunk_hash = hashlib.sha256(chunk_data).digest()
            if actual_chunk_hash != expected_chunk_hash:
                print(f"Chunk {seq} corrupted.")
                if seq in received_chunks:
                    del received_chunks[seq]
            else:
                received_chunks[seq] = chunk_data
                print(f"Received chunk {seq}.")
            if len(received_chunks) == total_chunks:
                break
        except socket.timeout:
            break
    # Request retransmission for missing chunks.
    missing = [seq for seq in range(total_chunks) if seq not in received_chunks]
    rounds = 0
    sock.settimeout(2)
    while missing and rounds < 5:
        print(f"Requesting retransmission for missing chunks: {missing}")
        req = b"REQ" + struct.pack("!I", len(missing))
        for seq in missing:
            req += struct.pack("!I", seq)
        send_msg(sock, req)
        round_start = time.time()
        while time.time() - round_start < 2:
            try:
                chunk_msg = recv_msg(sock)
                if chunk_msg is None:
                    break
                if len(chunk_msg) < 36:
                    continue
                seq = struct.unpack("!I", chunk_msg[:4])[0]
                expected_chunk_hash = chunk_msg[4:36]
                chunk_data = chunk_msg[36:]
                actual_chunk_hash = hashlib.sha256(chunk_data).digest()
                if actual_chunk_hash != expected_chunk_hash:
                    print(f"Retransmitted chunk {seq} still corrupted.")
                    if seq in received_chunks:
                        del received_chunks[seq]
                else:
                    received_chunks[seq] = chunk_data
                    print(f"Received retransmitted chunk {seq}.")
            except socket.timeout:
                break
        missing = [seq for seq in range(total_chunks) if seq not in received_chunks]
        rounds += 1
    if missing:
        print(f"Failed to receive all chunks, missing: {missing}")
    else:
        reassembled = b''.join(received_chunks[i] for i in sorted(received_chunks.keys()))
        actual_file_checksum = hashlib.sha256(reassembled).hexdigest()
        print(f"Reassembled file size: {len(reassembled)} bytes. Checksum: {actual_file_checksum}")
        if actual_file_checksum == expected_file_checksum:
            print("Transfer successful: Checksum verified!")
        else:
            print("Transfer failed: Checksum mismatch.")
    send_msg(sock, b"DONE")
    print("Sent DONE message to TCP server.")
    sock.close()

# --- UDP Client ---
def udp_client(file_path, server_host, server_port):
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return
    with open(file_path, "rb") as f:
        file_data = f.read()
    print(f"Read file {file_path} ({len(file_data)} bytes).")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (server_host, server_port)
    # Send file data with a length prefix.
    send_msg(sock, file_data, addr=server_addr, udp=True)
    print("File sent to UDP server.")
    # Receive header.
    header_msg, addr = recv_msg(sock, udp=True)
    if header_msg is None:
        print("No header received.")
        return
    total_chunks = struct.unpack("!I", header_msg[:4])[0]
    expected_file_checksum = header_msg[4:68].decode()
    print(f"Expecting {total_chunks} chunks with file checksum {expected_file_checksum}")
    received_chunks = {}
    sock.settimeout(2)
    while True:
        try:
            chunk_msg, addr = recv_msg(sock, udp=True)
            if chunk_msg is None:
                break
            if len(chunk_msg) < 36:
                continue
            seq = struct.unpack("!I", chunk_msg[:4])[0]
            expected_chunk_hash = chunk_msg[4:36]
            chunk_data = chunk_msg[36:]
            actual_chunk_hash = hashlib.sha256(chunk_data).digest()
            if actual_chunk_hash != expected_chunk_hash:
                print(f"Chunk {seq} corrupted.")
                if seq in received_chunks:
                    del received_chunks[seq]
            else:
                received_chunks[seq] = chunk_data
                print(f"Received chunk {seq}.")
            if len(received_chunks) == total_chunks:
                break
        except socket.timeout:
            break
    missing = [seq for seq in range(total_chunks) if seq not in received_chunks]
    rounds = 0
    sock.settimeout(2)
    while missing and rounds < 5:
        print(f"Requesting retransmission for missing chunks: {missing}")
        req = b"REQ" + struct.pack("!I", len(missing))
        for seq in missing:
            req += struct.pack("!I", seq)
        send_msg(sock, req, addr=server_addr, udp=True)
        round_start = time.time()
        while time.time() - round_start < 2:
            try:
                chunk_msg, addr = recv_msg(sock, udp=True)
                if chunk_msg is None:
                    break
                if len(chunk_msg) < 36:
                    continue
                seq = struct.unpack("!I", chunk_msg[:4])[0]
                expected_chunk_hash = chunk_msg[4:36]
                chunk_data = chunk_msg[36:]
                actual_chunk_hash = hashlib.sha256(chunk_data).digest()
                if actual_chunk_hash != expected_chunk_hash:
                    print(f"Retransmitted chunk {seq} still corrupted.")
                    if seq in received_chunks:
                        del received_chunks[seq]
                else:
                    received_chunks[seq] = chunk_data
                    print(f"Received retransmitted chunk {seq}.")
            except socket.timeout:
                break
        missing = [seq for seq in range(total_chunks) if seq not in received_chunks]
        rounds += 1
    if missing:
        print(f"Failed to receive all chunks, missing: {missing}")
    else:
        reassembled = b''.join(received_chunks[i] for i in sorted(received_chunks.keys()))
        actual_file_checksum = hashlib.sha256(reassembled).hexdigest()
        print(f"Reassembled file size: {len(reassembled)} bytes. Checksum: {actual_file_checksum}")
        if actual_file_checksum == expected_file_checksum:
            print("Transfer successful: Checksum verified!")
        else:
            print("Transfer failed: Checksum mismatch.")
    send_msg(sock, b"DONE", addr=server_addr, udp=True)
    print("Sent DONE message to UDP server.")
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client_sim.py <protocol: TCP/UDP> <server_host> <file_path>")
        sys.exit(1)
    protocol = sys.argv[1].upper()
    server_host = sys.argv[2]
    file_path = sys.argv[3]
    if protocol == "TCP":
        tcp_client(file_path, server_host, 5001)
    elif protocol == "UDP":
        udp_client(file_path, server_host, 5002)
    else:
        print("Unknown protocol. Use TCP or UDP.")
