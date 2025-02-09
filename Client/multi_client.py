# Client/multi_client.py

import threading
import socket
import os

# Server details
HOST = '127.0.0.1'  # Change to the server IP if needed
PORT = 5001
BUFFER_SIZE = 4096  

# List of files to send (ensure these exist)
FILES_TO_SEND = ["E:/BigEndian/Data/data.txt", "E:/BigEndian/Data/Random_data.txt", "E:/BigEndian/Data/Null_data.txt"]  # Add more as needed

def send_file(filename):
    try:
        if not os.path.exists(filename):
            print(f"Error: File '{filename}' not found.")
            return
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))

            # Send filename first
            client_socket.sendall(os.path.basename(filename).encode())

            # Send file content
            with open(filename, "rb") as file:
                while (data := file.read(BUFFER_SIZE)):
                    client_socket.sendall(data)

            print(f"File {filename} sent successfully.")

    except Exception as e:
        print(f"Error sending file {filename}: {e}")

# Creating multiple client threads
threads = []
for file in FILES_TO_SEND:
    thread = threading.Thread(target=send_file, args=(file,))
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

print("All files have been sent.")
