import socket
import random
import socket
import struct
import plistlib
from uuid import getnode as get_mac
from random import randint
import time

import dhcppython

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 67))
Mac=""
XID=""
TIMEOUT=10
BACKOFF_CUTOFF=120
INITIAL_INTERVAL=10
serverPort = 67
clientPort = 68




def buildPacket_discovery():
    global Mac,XID
    macb = getMacInBytes()
    Mac=macb
    transactionID = b''

    for i in range(4):
        t = randint(0, 255)
        transactionID += struct.pack('!B', t)
    XID=transactionID

    packet = b''
    packet += b'\x01'  # Message type: Boot Request (1)
    packet += b'\x01'  # Hardware type: Ethernet
    packet += b'\x06'  # Hardware address length: 6
    packet += b'\x00'  # Hops: 0
    packet += transactionID # Transaction ID
    packet += b'\x00\x00'  # Seconds elapsed: 0
    packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
    packet += b'\xEE\xC1\x9A\xD6\x3E\x00'   #Client MAC address:  "FF:C1:9A:D6:3E:00
    # packet += macb
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 67  # Server host name not given
    packet += b'\x00' * 125  # Boot file name not given
    packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    # DHCP IP Address
    packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

    return packet

def buildPacket_request(serverip , offerip):
    offerip = bytes(map(int, str(offerip).split('.')))
    serverip = bytes(map(int, str(serverip).split('.')))


    packet = b''
    packet += b'\x01'  # Message type: Boot Request (1)
    packet += b'\x01'  # Hardware type: Ethernet
    packet += b'\x06'  # Hardware address length: 6
    packet += b'\x00'  # Hops: 0

    # print(xid_hex)
    packet += XID # Transaction ID
    packet += b'\x00\x00'  # Seconds elapsed: 0
    packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
    packet +=offerip  # Your (client) IP address: 0.0.0.0
    packet += serverip  # Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
    # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += b'\xEE\xC1\x9A\xD6\x3E\x00'
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 67  # Server host name not given
    packet += b'\x00' * 125  # Boot file name not given
    packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    # DHCP IP Address
    packet += b'\x35\x01\x03'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

    return packet


def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12:
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2):
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    print(macb)
    return macb

def pkt_type(pkt):
    pkt = dhcppython.packet.DHCPPacket.from_bytes(pkt)
    print(pkt.options[0].value["dhcp_message_type"])


    return pkt.options[0].value["dhcp_message_type"]

def offerAndserverip(pkt):
    pkt = dhcppython.packet.DHCPPacket.from_bytes(pkt)
    print("client is offered  {}".format(pkt.yiaddr))
    print("Server address is {}".format(pkt.siaddr))
    return pkt.yiaddr, pkt.siaddr




if __name__ == '__main__':
    #send discovery
    sock.sendto(buildPacket_discovery(), ('<broadcast>', 68))
    # time.sleep(5)

    #offer

    msg, b = sock.recvfrom(1024)
    try:
        data = msg.decode()
        print(msg)
    except (UnicodeDecodeError, AttributeError):



        offerip , serverip=offerAndserverip(msg)
        print(offerip)

        sock.sendto(buildPacket_request(serverip,offerip), (str(serverip), 68))

        msg, b = sock.recvfrom(1024)
        print("Ack {}".format(msg))






