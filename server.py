# server2.py

#!/usr/bin/env python3
import socket
import threading
import struct
import hashlib
import random
import sys

CHUNK_SIZE = 1024  # bytes
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5001

# Error simulation parameters (for initial transmission only)
DROP_PROB = 0.2      # 20% chance to drop a chunk
CORRUPT_PROB = 0.1   # 10% chance to corrupt a chunk

# ---------------------------
# Helper functions for framing messages
# ---------------------------
def send_msg(sock, data: bytes):
    """Send a message preceded by its 4-byte length."""
    msg_length = struct.pack("!I", len(data))
    sock.sendall(msg_length + data)

def recv_msg(sock) -> bytes:
    """Receive a message preceded by its 4-byte length."""
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack("!I", raw_msglen)[0]
    return recvall(sock, msglen)

def recvall(sock, n) -> bytes:
    """Helper function to receive exactly n bytes."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def maybe_simulate_error(chunk: bytes, simulate_error: bool = True) -> bytes:
    """
    With error simulation enabled, randomly drop or corrupt a chunk.
    The chunk message format is:
      - 4 bytes: sequence number
      - 32 bytes: SHA256 digest of chunk data
      - remaining bytes: chunk data
    If dropped, return None; if corrupted, return a modified chunk.
    """
    if not simulate_error:
        return chunk
    r = random.random()
    if r < DROP_PROB:
        # Simulate drop: return None (do not send this chunk)
        return None
    elif r < DROP_PROB + CORRUPT_PROB:
        # Simulate corruption: flip a bit in the chunk data portion.
        seq = chunk[:4]
        chunk_hash = chunk[4:36]
        data = chunk[36:]
        if len(data) > 0:
            # Flip the first byte.
            corrupted_data = bytes([data[0] ^ 0xFF]) + data[1:]
        else:
            corrupted_data = data
        corrupted_chunk = seq + chunk_hash + corrupted_data
        return corrupted_chunk
    else:
        return chunk

# ---------------------------
# Client handler (supports multi-client)
# ---------------------------
def handle_client(conn: socket.socket, addr):
    try:
        print(f"[+] Connected by {addr}")
        # 1. Receive the file from the client.
        file_data = recv_msg(conn)
        if file_data is None:
            print("[-] No data received. Closing connection.")
            return
        print(f"[{addr}] Received file of {len(file_data)} bytes.")

        # 2. Compute the file checksum (SHA256) and prepare header.
        file_checksum = hashlib.sha256(file_data).hexdigest().encode()  # 64-byte ascii hex
        print(f"[{addr}] Computed file SHA256: {file_checksum.decode()}")

        # 3. Split the file into chunks and prepare chunk messages.
        total_chunks = (len(file_data) + CHUNK_SIZE - 1) // CHUNK_SIZE
        stored_chunks = {}   # Store correct chunk messages for potential retransmission.
        chunk_messages = []  # List of all chunk messages (to be shuffled).
        for seq in range(total_chunks):
            start = seq * CHUNK_SIZE
            end = start + CHUNK_SIZE
            chunk_data = file_data[start:end]
            # Compute per-chunk hash (raw 32-byte digest)
            chash = hashlib.sha256(chunk_data).digest()
            # Build chunk message: 4-byte seq + 32-byte chunk hash + chunk data.
            chunk_msg = struct.pack("!I", seq) + chash + chunk_data
            stored_chunks[seq] = chunk_msg
            chunk_messages.append(chunk_msg)

        # 4. Send header to client: total_chunks (4 bytes) + file_checksum (64 bytes).
        header_msg = struct.pack("!I", total_chunks) + file_checksum
        send_msg(conn, header_msg)
        print(f"[{addr}] Sent header: total_chunks={total_chunks}, file_checksum={file_checksum.decode()}")

        # 5. Shuffle chunks to simulate out-of-order delivery.
        random.shuffle(chunk_messages)

        # 6. Send each chunk with error simulation (only during initial transmission).
        for chunk_msg in chunk_messages:
            simulated = maybe_simulate_error(chunk_msg, simulate_error=True)
            if simulated is None:
                # Simulate drop: log and do not send this chunk.
                seq = struct.unpack("!I", chunk_msg[:4])[0]
                print(f"[{addr}] Dropped chunk {seq} (simulated).")
                continue
            send_msg(conn, simulated)
        print(f"[{addr}] Initial transmission of chunks complete.")

        # 7. Retransmission loop: wait for client requests.
        conn.settimeout(10)  # wait up to 10 seconds for retransmission requests
        max_rounds = 5
        rounds = 0
        while rounds < max_rounds:
            try:
                req_msg = recv_msg(conn)
                if req_msg is None:
                    print(f"[{addr}] No retransmission request received. Ending transmission.")
                    break
                if req_msg.startswith(b"REQ"):
                    # Retransmission request received.
                    count = struct.unpack("!I", req_msg[3:7])[0]
                    missing_seqs = []
                    for i in range(count):
                        seq = struct.unpack("!I", req_msg[7 + i*4: 7 + (i+1)*4])[0]
                        missing_seqs.append(seq)
                    print(f"[{addr}] Received retransmission request for chunks: {missing_seqs}")
                    # Resend the requested chunks (without error simulation).
                    for seq in missing_seqs:
                        if seq in stored_chunks:
                            send_msg(conn, stored_chunks[seq])
                            print(f"[{addr}] Resent chunk {seq}.")
                    rounds += 1
                elif req_msg == b"DONE":
                    print(f"[{addr}] Client indicates completion.")
                    break
                else:
                    print(f"[{addr}] Unknown message type received: {req_msg[:10]}")
            except socket.timeout:
                print(f"[{addr}] Retransmission wait timeout reached.")
                break

    except Exception as e:
        print(f"[-] Exception with {addr}: {e}")
    finally:
        conn.close()
        print(f"[{addr}] Connection closed.")

# ---------------------------
# Main server loop
# ---------------------------
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()
        print(f"[*] Server listening on {SERVER_HOST}:{SERVER_PORT}")
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
        sys.exit(0)
