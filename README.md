# TCP based File Transfer with Checksum and RSA Encryption

## Overview
This project is a file transfer system that ensures reliable communication between a client and a server using **TCP sockets**. The system is designed to handle file transmission, retransmissions in case of packet loss, and provide a robust mechanism for data integrity verification.

## Objective
The goal was to develop and test a **client-server file transfer application**, ensuring:
- Correct file transmission.
- Reliable handling of retransmission requests.
- Data integrity validation.

## Existing Solution: TCP-based File Transfer
Currently, the implementation uses **TCP** for file transmission. The advantages of TCP include:
- Reliable, ordered, and error-checked delivery.
- Built-in congestion control and retransmission mechanisms.

### Possible Improvements
While TCP ensures reliability, **UDP-based file transfer** with custom reliability mechanisms could be more efficient for large file transfers, reducing latency. A UDP-based approach would:
- Avoid connection overhead, making it faster for large file transfers.
- Allow fine-tuned control over retransmissions (e.g., selective acknowledgments).
- Be useful for real-time applications, where lower latency is critical.

## Alternative Approaches
### Flask-based API for File Transfer
Instead of raw socket programming, a **Flask-based REST API** could handle file uploads/downloads using HTTP. This approach would:
- Simplify the client-server interaction by leveraging HTTP methods (POST/GET).
- Allow easier integration with web-based clients.
- Support authentication and security features like JWT.

### Dockerized Deployment
To ensure portability and ease of deployment, **Docker** can be used to containerize the client and server. Benefits include:
- Consistency across different environments.
- Simplified dependency management.
- Scalability when deploying in cloud environments.
- 
---
## Testing and Validation
The project includes **unit tests**, manual and using `pytest` to verify:
- The client successfully sends a file to the server.
- The server correctly receives and stores the file.
- The retransmission mechanism functions correctly.
### Testing Report
  - Out-of-Order Delivery
      - The server shuffles the chunks before sending them.
      - The client reassembles the file correctly based on sequence numbers.
      - The file reassembly process is robust, ensuring correctness even when chunks arrive out of order.
![image](https://github.com/user-attachments/assets/20fac39b-28ad-4d19-91c5-6b129182658b)

  - Concurrency Testing
    - Used multi_client.py script and manually started multiple clients to simulate high load.
    - Each client session remains isolated with no cross-session interference.
    - The server handles multiple concurrent threads without performance degradation or session mixing.
    - However, performance degrades when using multi_client.py due to high memory consumption.
    - Workaround: Running multiple instances of the standard client script in different terminals works better.
![image](https://github.com/user-attachments/assets/397fff70-ec53-490b-b0a7-94ba2245cc69)

  - Performance Testing
    - Tested with large files (100MB+).
    - Performance degrades gracefully, ensuring file integrity throughout transmission.
    - Optimization added:
      - If file size exceeds 100MB, chunk size increases to 1MB instead of the default 1024 bytes.
      - Prevents excessive memory usage, significantly improving performance.
    - Successfully tested 2GB file transfer, and it worked as expected.
![image](https://github.com/user-attachments/assets/8b3c495b-793e-475b-9d62-5f245e3bee1d)
    - Packet loss if notified and retransmitted
![image](https://github.com/user-attachments/assets/5c168f0f-a7d6-4542-a0ad-e4830169fb2d)


  - Boundary Testing
    - Tested with varying file sizes (1 byte, 1 KB, 1 MB, etc.) — all worked as expected.
    - Binary data integrity is maintained, and hash verification is accurate.
    - Created a folder on both client and server to store a copy of the transmitted files for verification.
    - Uploaded files with random binary data — integrity preserved.
![image](https://github.com/user-attachments/assets/20fac39b-28ad-4d19-91c5-6b129182658b)
    - Data copy at the client and the server for verification
![image](https://github.com/user-attachments/assets/a92475c3-2d09-4ad3-bacd-20766c9edded)

  - High Concurrency Testing
    - Increased the number of simultaneous clients significantly.
    - Server maintained good throughput and responsiveness but showed memory issues under high stress.
    - Needs further optimization to improve memory handling.
  - Integration Testing
    - Verified checksum integrity:
      - The checksum computed externally matches the server-provided checksum and the client-computed checksum.

  - Automated Testing using PyTest
    - Sample Test Cases
    - ✅ `test_client_sends_file`: Ensures the client sends data correctly.
    - ✅ `test_server_receives_file`: Verifies the server correctly receives and stores the file.
![image](https://github.com/user-attachments/assets/be34bfcb-4784-4bfa-8c31-7c133b2c126e)

---
## TCP-UDP Hybrid Server
![image](https://github.com/user-attachments/assets/64130951-a87b-4c56-89b8-66ea731851cc)
### It Can be extended a SOC Surveillance System
  - Control Channel (TCP):
    - Use TCP for setting up connections, negotiating stream parameters, and sending control messages (e.g., pan/tilt commands, motion alerts, or video configuration).
    - A TCP-based protocol can ensure that commands are reliably delivered and acknowledged.
  - Data Channel (UDP):
    - Use UDP for streaming live video feeds. Protocols like RTP (Real-Time Protocol) are commonly used in conjunction with UDP for streaming media.
    - RTCP (Real-Time Control Protocol) can be used alongside RTP to provide feedback about the quality of the stream, which might then be used to request retransmissions (or adjustments) via the TCP channel if necessary.
  - Example in Practice:
    - RTSP/RTP Hybrid: Many IP cameras use RTSP (which runs over TCP) to establish and control the media session, and then stream video using RTP over UDP. RTSP handles session control (start, pause, teardown), while RTP is optimized for low-latency delivery of continuous streams.
    - Enhanced Reliability: The system could also implement application-level FEC (Forward Error Correction) on the UDP stream. If a few packets are lost, the receiver can reconstruct the missing parts without needing to request retransmission immediately.
    - Alternatively, if the system detects significant packet loss in UDP, it could signal over the TCP channel to adjust parameters (or even temporarily switch to a more reliable mode).

---
## Simulation in a Shared Memory Approach
  - Dockekerized the environment for mimic Linux environment and smooth deployment
    ![image](https://github.com/user-attachments/assets/0fb78d9c-b2ac-40ed-8971-90eb448c5ec8)
  - Running the shared memory environment
    - Start one container interactively
      ![image](https://github.com/user-attachments/assets/4be64f43-e91b-4042-9c4e-cf7204a9563e)
    - Open another shell in the same container using
      ![image](https://github.com/user-attachments/assets/3598f067-ca6c-4db9-98c3-5bae3d2d6454)
    - Create 4 bash shell
      - 1 for manager_server
      - 1 for the server
      - 2 for the clients (can be more)

![image](https://github.com/user-attachments/assets/312cd2e1-d850-4896-b82d-56aee2383ead)
### The file is segmented into chunks and sent over the network.

![image](https://github.com/user-attachments/assets/7ba7b857-2d08-4f09-b6fe-c05fb782b774)
### Packet Loss and Packet Curruption has been simulated to mimic the actual network.



---
## Encryption process and Data Transfer
### Create an RSA Key Pair
- Generate these keys using OpenSSL on your host machine (or inside the container) with the following commands:
- Generate the Private Key:
  ```bash
  openssl genrsa -out server_private.pem 2048
  ```
- This creates a 2048-bit RSA private key and saves it to server_private.pem.
- Generate the Public Key:

  ```bash
  openssl rsa -in server_private.pem -pubout -out server_public.pem
  ```
- This extracts the public key from the private key and saves it to server_public.pem.

### Key Transfer - RSA for Key Exchange
  - Server RSA Key Pair: The server has an RSA key pair—a public key and a private key.
  - Sending Public Key: When a client connects, the server sends its RSA public key to the client.
  - Client Generates AES Key: The client generates a random 256‑bit AES key (and usually an initialization vector, IV).
  - Encrypting the AES Key: The client encrypts this AES key using the server's RSA public key.
  - Sending Encrypted AES Key: The client sends the RSA‑encrypted AES key to the server.
  - Server Decrypts AES Key: The server uses its RSA private key to decrypt the encrypted AES key, and now both sides share the same AES key (and IV).
### Data Transfer - AES for Data Encryption:
  - Symmetric Encryption: Once the AES key is established, both client and server use it to encrypt and decrypt the actual file data (or any subsequent messages) using a symmetric algorithm (like AES‑256‑CBC).
  - Efficiency: AES is fast and efficient for encrypting large amounts of data, which is why it’s used for the file transfer instead of RSA.
  - IV Usage: The Initialization Vector (IV) ensures that identical plaintext blocks encrypt differently, improving security. The IV is typically sent in plaintext (or in a non-confidential manner) because it does not need to be secret—only unpredictable.


## Future Improvements
- Add a **web interface** for file upload/download.
- Improve **test coverage** with integration tests.
- Use ephemeral key exchanges (e.g., Diffie-Hellman/ECDHE) for forward secrecy.
- Add HMAC or digital signatures for integrity and authenticity.
- Implement certificate-based authentication.
- Integrate compression before encryption.
- Improve error correction beyond simple retransmission.
- Add detailed logging and monitoring for security and performance.
- Expand support for real-world network conditions.

