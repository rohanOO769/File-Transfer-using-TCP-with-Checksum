# simulation/server_sim.py

import socket, threading, struct, hashlib, random, sys, time, os

# --- Configuration ---
TCP_HOST = '0.0.0.0'
TCP_PORT = 5001
UDP_HOST = '0.0.0.0'
UDP_PORT = 5002

DROP_PROB = 0.2      # 20% chance to drop a chunk
CORRUPT_PROB = 0.1   # 10% chance to corrupt a chunk

server_folder = "server_data"
os.makedirs(server_folder, exist_ok=True)

# --- Helper functions for message framing ---
def send_msg(sock, data: bytes, addr=None):
    """Send a message with a 4-byte length prefix. If addr is provided, use sendto()."""
    msg_length = struct.pack("!I", len(data))
    if addr:
        sock.sendto(msg_length + data, addr)
    else:
        sock.sendall(msg_length + data)

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

def recvall(sock, n):
    """Helper to receive exactly n bytes."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def maybe_simulate_error(chunk: bytes, simulate_error=True):
    """
    With error simulation enabled, randomly drop or corrupt a chunk.
    The chunk format is:
       - 4 bytes: sequence number
       - 32 bytes: SHA256 digest of the chunk data
       - remaining: chunk data.
    """
    if not simulate_error:
        return chunk
    r = random.random()
    if r < DROP_PROB:
        return None  # Simulate drop.
    elif r < DROP_PROB + CORRUPT_PROB:
        seq = chunk[:4]
        chunk_hash = chunk[4:36]
        data = chunk[36:]
        if len(data) > 0:
            # Flip one bit in the first byte.
            corrupted_data = bytes([data[0] ^ 0xFF]) + data[1:]
        else:
            corrupted_data = data
        corrupted_chunk = seq + chunk_hash + corrupted_data
        return corrupted_chunk
    else:
        return chunk

# --- TCP Server Handler ---
def handle_tcp_client(conn, addr):
    try:
        print(f"[TCP] Connected by {addr}")
        # 1. Receive file from client.
        file_data = recv_msg(conn)
        if file_data is None:
            print("[-] No data received from", addr)
            return
        file_size = len(file_data)
        print(f"[TCP] Received file of {file_size} bytes from {addr}.")

        # 2. Determine chunk size.
        if file_size > 100 * 1024 * 1024:
            chunk_size = 1024 * 1024  # 1 MB
        else:
            chunk_size = 1024         # 1 KB

        # 3. Compute overall file checksum.
        file_checksum = hashlib.sha256(file_data).hexdigest().encode()  # 64-byte hex
        total_chunks = (file_size + chunk_size - 1) // chunk_size

        # 4. Split file into chunks.
        stored_chunks = {}
        chunk_messages = []
        for seq in range(total_chunks):
            start = seq * chunk_size
            end = start + chunk_size
            chunk_data = file_data[start:end]
            chash = hashlib.sha256(chunk_data).digest()  # raw 32-byte digest
            chunk_msg = struct.pack("!I", seq) + chash + chunk_data
            stored_chunks[seq] = chunk_msg
            chunk_messages.append(chunk_msg)

        # 5. Send header: total_chunks + file checksum.
        header_msg = struct.pack("!I", total_chunks) + file_checksum
        send_msg(conn, header_msg)
        print(f"[TCP] Sent header to {addr}: total_chunks={total_chunks}, checksum={file_checksum.decode()}")

        # 6. Shuffle and send chunks (simulate out-of-order delivery and errors).
        random.shuffle(chunk_messages)
        for chunk_msg in chunk_messages:
            simulated = maybe_simulate_error(chunk_msg, simulate_error=True)
            if simulated is None:
                seq = struct.unpack("!I", chunk_msg[:4])[0]
                print(f"[TCP] Dropped chunk {seq} (simulated) for {addr}.")
                continue
            send_msg(conn, simulated)
        print(f"[TCP] Initial transmission complete to {addr}.")

        # 7. Retransmission loop.
        conn.settimeout(10)
        rounds = 0
        while rounds < 5:
            try:
                req_msg = recv_msg(conn)
                if req_msg is None:
                    break
                if req_msg.startswith(b"REQ"):
                    count = struct.unpack("!I", req_msg[3:7])[0]
                    missing_seqs = []
                    for i in range(count):
                        seq = struct.unpack("!I", req_msg[7 + i*4: 7 + (i+1)*4])[0]
                        missing_seqs.append(seq)
                    print(f"[TCP] Received retransmission request from {addr} for chunks: {missing_seqs}")
                    for seq in missing_seqs:
                        if seq in stored_chunks:
                            send_msg(conn, stored_chunks[seq])
                            print(f"[TCP] Resent chunk {seq} to {addr}.")
                    rounds += 1
                elif req_msg == b"DONE":
                    print(f"[TCP] Client {addr} indicated completion.")
                    server_filename = os.path.join(server_folder, f"received_{addr[0]}_{int(time.time())}.bin")
                    with open(server_filename, "wb") as f:
                        f.write(file_data)
                    print(f"[TCP] Saved file from {addr} to {server_filename}")
                    break
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] Exception with TCP client {addr}: {e}")
    finally:
        conn.close()
        print(f"[TCP] Connection closed for {addr}")

# --- UDP Server Handler ---
def handle_udp_client(udp_sock):
    print("[UDP] UDP server thread started.")
    clients = {}  # Map client address -> client state
    while True:
        try:
            data, addr = udp_sock.recvfrom(65535)
            if not data:
                continue
            # Assume first message from a client is the complete file data (with a 4-byte length prefix).
            if addr not in clients:
                if len(data) < 4:
                    continue
                file_len = struct.unpack("!I", data[:4])[0]
                file_data = data[4:]
                if len(file_data) != file_len:
                    print(f"[UDP] Incomplete file data from {addr}.")
                    continue
                print(f"[UDP] Received file from {addr}, size {len(file_data)} bytes.")
                # Process the file as in the TCP handler.
                file_size = len(file_data)
                if file_size > 64 * 1024:
                    chunk_size = 63 * 1024 # 63KB 
                else:
                    chunk_size = 1024
                file_checksum = hashlib.sha256(file_data).hexdigest().encode()
                total_chunks = (file_size + chunk_size - 1) // chunk_size
                stored_chunks = {}
                chunk_messages = []
                for seq in range(total_chunks):
                    start = seq * chunk_size
                    end = start + chunk_size
                    chunk_data = file_data[start:end]
                    chash = hashlib.sha256(chunk_data).digest()
                    chunk_msg = struct.pack("!I", seq) + chash + chunk_data
                    stored_chunks[seq] = chunk_msg
                    chunk_messages.append(chunk_msg)
                header_msg = struct.pack("!I", total_chunks) + file_checksum
                send_msg(udp_sock, header_msg, addr)
                print(f"[UDP] Sent header to {addr}: total_chunks={total_chunks}, checksum={file_checksum.decode()}")
                random.shuffle(chunk_messages)
                for chunk_msg in chunk_messages:
                    simulated = maybe_simulate_error(chunk_msg, simulate_error=True)
                    if simulated is None:
                        seq = struct.unpack("!I", chunk_msg[:4])[0]
                        print(f"[UDP] Dropped chunk {seq} (simulated) for {addr}.")
                        continue
                    send_msg(udp_sock, simulated, addr)
                print(f"[UDP] Initial transmission complete to {addr}.")
                clients[addr] = {"file_data": file_data}  # Save state if needed.
            else:
                # Handle retransmission requests or DONE messages.
                if data.startswith(b"REQ"):
                    print(f"[UDP] Received retransmission request from {addr} (not implemented in simulation).")
                elif data == b"DONE":
                    print(f"[UDP] Client {addr} indicated completion.")
                    file_data = clients[addr]["file_data"]
                    server_filename = os.path.join(server_folder, f"received_{addr[0]}_{int(time.time())}.bin")
                    with open(server_filename, "wb") as f:
                        f.write(file_data)
                    print(f"[UDP] Saved file from {addr} to {server_filename}")
                    del clients[addr]
        except Exception as e:
            print(f"[-] Exception in UDP server: {e}")

# --- Server main functions ---
def tcp_server():
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind((TCP_HOST, TCP_PORT))
    tcp_sock.listen()
    print(f"[TCP] Server listening on {TCP_HOST}:{TCP_PORT}")
    while True:
        conn, addr = tcp_sock.accept()
        t = threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True)
        t.start()

def udp_server():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((UDP_HOST, UDP_PORT))
    print(f"[UDP] Server listening on {UDP_HOST}:{UDP_PORT}")
    handle_udp_client(udp_sock)

if __name__ == "__main__":
    t_tcp = threading.Thread(target=tcp_server, daemon=True)
    t_udp = threading.Thread(target=udp_server, daemon=True)
    t_tcp.start()
    t_udp.start()
    print("Server running (TCP on port 5001, UDP on port 5002). Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Server shutting down.")
