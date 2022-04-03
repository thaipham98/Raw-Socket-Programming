# Raw-Socket-Programming
In this file, you should briefly describe your high-level approach, what TCP/IP features you 
implemented, and any challenges you faced. You must also include a detailed description of which 
student worked on which part of the code.

1. High-Level Approach (or major steps that we take in order to complete this project, not in order):
- We first review our knowledge regarding IP and TCP so that we can have the best understanding
before implementing the project. Our implementation is layer-by-layer.
- Create correct type of raw socket and make sure that they receive and send data following correct 
protocol.
- Create TCP & IP headers and perform checksum (consulted Silver Moon's Raw Socket Tutorial)
- Implement three-way handshake protocol to establish connection between client and server
- Monitor the packets received, then unpack the IP_Datagram and check validity (filter) layer by layer
- Close connection after receiving complete data
- Validate URL parameter and run HTTP GET request, extract body/data from HTTP response and validate it
- Create file to write data in
- Validated the received data by using "diff" commands
- Create Makefile, README, and follow any other miscellaneous requirements left.

2. TCP/IP Features
3. Challenges
4. 
