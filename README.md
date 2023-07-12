# DHCP


## Project Overview

In this project, we aim to simulate a client and server in the DHCP protocol and implement the IP allocation service to network hosts. Please note that this project is solely a simulation and does not provide actual internet connectivity using the assigned IP addresses.

## Server Execution Process

The general execution process for the server is as follows:

1. The server is executed and is always ready to receive Discovery messages.
2. When a Discovery message is received by the server, it sends an Offer and then waits to receive a Request.
3. After receiving the Request, the server sends an Acknowledgment (Ack) message.

## Client Execution Process

The general execution process for the client is as follows:

1. The client is executed and sends a Discovery message.
2. The client waits for an Offer from the server.
3. Upon receiving the Offer, the client sends a Request message.
4. The client waits for an Acknowledgment (Ack) to confirm the IP allocation.
5. After receiving the Ack, the client should display the received IP in the terminal.




