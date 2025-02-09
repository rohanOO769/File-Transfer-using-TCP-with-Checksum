# test_server.py

import pytest
import socket
import struct
import threading
import os
import time
from server import main as start_server

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5001

@pytest.fixture(scope="module")
def server():
    """Start the server in a separate thread."""
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    time.sleep(2)  # Give server time to start
    yield
    print("\n[!] Stopping server.")

def send_msg(sock, data: bytes):
    """Send a message preceded by its 4-byte length."""
    msg_length = struct.pack("!I", len(data))
    sock.sendall(msg_length + data)

def recv_msg(sock):
    """Receive a message with a 4-byte length prefix."""
    raw_msglen = sock.recv(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack("!I", raw_msglen)[0]
    return sock.recv(msglen)

def test_server_receives_file(server):
    """Test if the server correctly receives a file."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))
        test_data = b"Hello, this is a test file."
        send_msg(sock, test_data)

        # Expect a response (header containing total_chunks and checksum)
        response = recv_msg(sock)
        assert response is not None
        print(f"[Test] Server response: {response}")


