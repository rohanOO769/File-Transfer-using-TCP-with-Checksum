# simulation/UDP_client.py

import socket, struct, hashlib, sys, os, time

# --- Helper functions (same as before) ---
def send_msg(sock, data: bytes, addr=None, udp=False):
    """Send a message with a 4-byte length prefix."""
    msg_length = struct.pack("!I", len(data))
    if udp:
        sock.sendto(msg_length + data, addr)
    else:
        sock.sendall(msg_length + data)

def recv_msg(sock, udp=False):
    """Receive a message with a 4-byte length prefix.
       For UDP, returns (data, addr)."""
    if not udp:
        data = recvall(sock, 4)
        if not data:
            return None
        msglen = struct.unpack("!I", data)[0]
        return recvall(sock, msglen)
    else:
        data, addr = sock.recvfrom(65535)
        if len(data) < 4:
            return None, addr
        msglen = struct.unpack("!I", data[:4])[0]
        return data[4:], addr

def recvall(sock, n):
    """Helper to receive exactly n bytes (TCP only)."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# --- Updated UDP Client with Segmentation ---
def udp_client(file_path, server_host, server_port):
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return

    # Read the entire file.
    with open(file_path, "rb") as f:
        file_data = f.read()
    file_size = len(file_data)
    print(f"Read file {file_path} ({file_size} bytes).")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (server_host, server_port)

    # Define a segment size that is safely below the UDP datagram limit.
    segment_size = 60000  # 60 KB (adjust as needed)
    total_segments = (file_size + segment_size - 1) // segment_size
    print(f"Segmenting file into {total_segments} segments.")

    # --- Send header message ---
    # Format: "HDR" (3 bytes) + total_segments (4 bytes) + file_size (4 bytes)
    header = b"HDR" + struct.pack("!I", total_segments) + struct.pack("!I", file_size)
    send_msg(sock, header, addr=server_addr, udp=True)
    print("Sent header to server.")

    # --- Send file segments ---
    for seq in range(total_segments):
        start = seq * segment_size
        end = start + segment_size
        segment = file_data[start:end]
        # Format each segment: "SEG" (3 bytes) + sequence number (4 bytes) + segment data
        seg_msg = b"SEG" + struct.pack("!I", seq) + segment
        send_msg(sock, seg_msg, addr=server_addr, udp=True)
        print(f"Sent segment {seq + 1}/{total_segments}")

    # --- (The remainder of the protocol remains similar) ---
    # Now the client waits for the server to process the file and send back the header and chunks.
    header_msg, addr = recv_msg(sock, udp=True)
    if header_msg is None:
        print("No header received from server.")
        return
    total_chunks = struct.unpack("!I", header_msg[:4])[0]
    expected_file_checksum = header_msg[4:68].decode()
    print(f"Expecting {total_chunks} chunks with file checksum {expected_file_checksum}")

    received_chunks = {}
    sock.settimeout(2)
    # Receive initial chunks.
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

    # Retransmission logic as before...
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
        print("Usage: python client_sim.py UDP <server_host> <file_path>")
        sys.exit(1)
    protocol = sys.argv[1].upper()
    server_host = sys.argv[2]
    file_path = sys.argv[3]
    if protocol == "UDP":
        udp_client(file_path, server_host, 5002)
    else:
        print("This example is for UDP segmentation only.")
