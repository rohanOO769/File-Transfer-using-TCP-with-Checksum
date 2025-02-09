# TCP based File Transfer with Checksum

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

## Future Improvements
- Implement a **UDP-based** protocol with selective acknowledgments.
- Add a **web interface** for file upload/download.
- Improve **test coverage** with integration tests.
- **Dockerize** the client and server for better deployment.

