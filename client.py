# client2.py

#!/usr/bin/env python3
import socket
import struct
import hashlib
import sys
import os
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001
CHUNK_SIZE = 1024  # must match server

# ---------------------------
# Helper functions for message framing
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

# ---------------------------
# Main client function
# ---------------------------
def main(file_path):
    # 1. Read the file.
    if not os.path.exists(file_path):
        print(f"[-] File '{file_path}' does not exist.")
        return
    with open(file_path, "rb") as f:
        file_data = f.read()
    print(f"[+] Read file '{file_path}' ({len(file_data)} bytes).")

    # 2. Connect to the server.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[+] Connected to server {SERVER_HOST}:{SERVER_PORT}")

        # 3. Send the file to the server.
        send_msg(sock, file_data)
        print("[*] File sent to server.")

        # 4. Receive header: total_chunks (4 bytes) + file_checksum (64 bytes).
        header_msg = recv_msg(sock)
        if header_msg is None:
            print("[-] Did not receive header from server.")
            return
        total_chunks = struct.unpack("!I", header_msg[:4])[0]
        expected_file_checksum = header_msg[4:68].decode()  # 64-byte hex string
        print(f"[+] Expecting {total_chunks} chunks with file checksum: {expected_file_checksum}")

        # 5. Receive initial chunk messages.
        # Each chunk message format: 4 bytes seq + 32 bytes chunk hash + chunk data.
        received_chunks = {}
        sock.settimeout(2)  # short timeout for the initial round
        while True:
            try:
                chunk_msg = recv_msg(sock)
                if chunk_msg is None:
                    break
                if len(chunk_msg) < 36:
                    print("[-] Received an invalid chunk message (too short).")
                    continue
                seq = struct.unpack("!I", chunk_msg[:4])[0]
                expected_chunk_hash = chunk_msg[4:36]  # raw digest (32 bytes)
                chunk_data = chunk_msg[36:]
                # Verify the chunk's integrity.
                actual_chunk_hash = hashlib.sha256(chunk_data).digest()
                if actual_chunk_hash != expected_chunk_hash:
                    print(f"[*] Chunk {seq} corrupted (hash mismatch).")
                    # Do not store; mark as missing.
                    if seq in received_chunks:
                        del received_chunks[seq]
                else:
                    received_chunks[seq] = chunk_data
                    print(f"    Received chunk {seq} ({len(chunk_data)} bytes).")
            except socket.timeout:
                # Timeout indicates the end of the initial batch.
                break
            # Optionally, if all chunks are received, break early.
            if len(received_chunks) == total_chunks:
                break

        # 6. Identify missing (or corrupted) chunks.
        missing = [seq for seq in range(total_chunks) if seq not in received_chunks]
        print(f"[+] Initially received {len(received_chunks)}/{total_chunks} chunks.")

        # 7. Retransmission loop: request missing chunks.
        rounds = 0
        max_rounds = 5
        sock.settimeout(2)  # timeout for each retransmission round
        while missing and rounds < max_rounds:
            print(f"[*] Requesting retransmission for missing chunks: {missing}")
            # Build retransmission request message.
            # Format: b"REQ" + 4 bytes (count) + 4 bytes per missing chunk.
            req = b"REQ" + struct.pack("!I", len(missing))
            for seq in missing:
                req += struct.pack("!I", seq)
            send_msg(sock, req)

            # Wait for retransmitted chunks.
            round_start = time.time()
            while time.time() - round_start < 2:
                try:
                    chunk_msg = recv_msg(sock)
                    if chunk_msg is None:
                        break
                    if len(chunk_msg) < 36:
                        print("[-] Received an invalid chunk message during retransmission.")
                        continue
                    seq = struct.unpack("!I", chunk_msg[:4])[0]
                    expected_chunk_hash = chunk_msg[4:36]
                    chunk_data = chunk_msg[36:]
                    actual_chunk_hash = hashlib.sha256(chunk_data).digest()
                    if actual_chunk_hash != expected_chunk_hash:
                        print(f"[*] Retransmitted chunk {seq} still corrupted.")
                        if seq in received_chunks:
                            del received_chunks[seq]
                    else:
                        received_chunks[seq] = chunk_data
                        print(f"    Received retransmitted chunk {seq} ({len(chunk_data)} bytes).")
                except socket.timeout:
                    break
            missing = [seq for seq in range(total_chunks) if seq not in received_chunks]
            rounds += 1

        if missing:
            print(f"[-] Failed to receive all chunks after retransmission attempts: missing {missing}")
        else:
            # 8. Reassemble the file.
            reassembled = b''.join(received_chunks[i] for i in sorted(received_chunks.keys()))
            print(f"[+] Reassembled file size: {len(reassembled)} bytes.")
            # 9. Verify overall file checksum.
            actual_file_checksum = hashlib.sha256(reassembled).hexdigest()
            print(f"[+] Computed file checksum: {actual_file_checksum}")
            if actual_file_checksum == expected_file_checksum:
                print("[*] Transfer Successful: Checksum verified!")
            else:
                print("[-] Transfer Failed: Checksum mismatch.")

        # 10. Inform the server that the transfer is complete.
        send_msg(sock, b"DONE")
        print("[*] Sent DONE message to server.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <path_to_file>")
        sys.exit(1)
    file_path = sys.argv[1]
    main(file_path)
