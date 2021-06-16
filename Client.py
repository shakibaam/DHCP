import ipaddress
import socket
import random
import socket
import struct
import plistlib
from uuid import getnode as get_mac
from random import randint
from time import *
import threading

import dhcppython

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 67))
Mac = ""
XID = ""
TIMEOUT = 10
BACKOFF_CUTOFF = 120
INITIAL_INTERVAL = 10
serverPort = 67
clientPort = 68


def buildPacket_discovery(mac):
    mac = str(mac).replace(":", "")
    mac = bytes.fromhex(mac)
    global Mac, XID
    # macb = getMacInBytes()
    Mac = mac
    print(Mac)
    transactionID = b''

    for i in range(4):
        t = randint(0, 255)
        transactionID += struct.pack('!B', t)
    XID = transactionID
    print(XID)

    packet = b''
    packet += b'\x01'  # Message type: Boot Request (1)
    packet += b'\x01'  # Hardware type: Ethernet
    packet += b'\x06'  # Hardware address length: 6
    packet += b'\x00'  # Hops: 0
    packet += transactionID  # Transaction ID
    packet += b'\x00\x00'  # Seconds elapsed: 0
    packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
    packet += mac  # Client MAC address:  "FF:C1:9A:D6:3E:00
    # packet += macb
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 67  # Server host name not given
    packet += b'\x00' * 125  # Boot file name not given
    packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    # DHCP IP Address
    packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

    return packet


def buildPacket_request(serverip, offerip):
    offerip = bytes(map(int, str(offerip).split('.')))
    serverip = bytes(map(int, str(serverip).split('.')))
    global Mac

    packet = b''
    packet += b'\x01'  # Message type: Boot Request (1)
    packet += b'\x01'  # Hardware type: Ethernet
    packet += b'\x06'  # Hardware address length: 6
    packet += b'\x00'  # Hops: 0

    # print(xid_hex)
    packet += XID  # Transaction ID
    packet += b'\x00\x00'  # Seconds elapsed: 0
    packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
    packet += offerip  # Your (client) IP address: 0.0.0.0
    packet += serverip  # Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
    # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += Mac
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 67  # Server host name not given
    packet += b'\x00' * 125  # Boot file name not given
    packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    # DHCP IP Address
    packet += b'\x35\x01\x03'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

    return packet



def pkt_type(packet):
    if packet[len(packet) - 1] == 2:
        return "DHCPOFFER"
    if packet[len(packet) - 1] == 5:
        return "DHCPACK"



def parse_packet_client(pkt):
   yiaddr_bytes=pkt[16:20]
   yiaddr_original=ipaddress.IPv4Address(yiaddr_bytes)
   siaddr_bytes=pkt[20:24]
   siaddr_original=ipaddress.IPv4Address(siaddr_bytes)

   return yiaddr_original, siaddr_original


def start_process(mac):
    offerip = ""
    sock.sendto(buildPacket_discovery(mac), ('<broadcast>', 68))

    # offer

    msg, b = sock.recvfrom(1024)
    try:
        data = msg.decode()

    except (UnicodeDecodeError, AttributeError):
        print("offer {}".format(msg))

        offerip, serverip = parse_packet_client(msg)
        print(offerip)

        sock.sendto(buildPacket_request(serverip, offerip), (str(serverip), 68))
        print("send request")

        msg, b = sock.recvfrom(1024)
        print("Ack {}".format(msg))


def discovery_timer(initial_interval):
    global dis_time
    dis_time = initial_interval

    while dis_time:
        mins, secs = divmod(dis_time, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        # print(timer)
        sleep(1)
        dis_time -= 1

def time_out():
    global timeOut
    timeOut=2

    while timeOut:
        mins, secs = divmod(timeOut, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        # print(timer)
        sleep(1)
        timeOut -= 1





if __name__ == '__main__':
    mac = input("Enter your mac address")
    # time=INITIAL_INTERVAL
    offer_ip=""
    flag=True
    ds_time=INITIAL_INTERVAL

    while flag:
        sock.sendto(buildPacket_discovery(mac), ('<broadcast>', 68))
        get_ip=False
        timer_thread=threading.Thread(target=discovery_timer,args=(ds_time,))
        timer_thread.start()
        while dis_time>0:



        # offer

            msg, b = sock.recvfrom(1024)
            try:
                data = msg.decode()
            except (UnicodeDecodeError, AttributeError):

                offerip, serverip = parse_packet_client(msg)
                print("offer {}:".format(msg))
                print(offerip)

                sock.sendto(buildPacket_request(serverip, offerip), (str(serverip), 68))
                print("send request")
                getAck=False
                time_out_thread=threading.Thread(target=time_out)
                time_out_thread.start()

                while timeOut>0:


                    msg, b = sock.recvfrom(1024)
                    if msg:
                        print("Ack {}".format(msg))
                        getAck=True
                    # if getAck:
                    #     flag=False
                if getAck==False:
                    print("time out!!")
                    continue
                else:
                    print("No time out :)")
                    get_ip=True



        if get_ip:
            flag=False
        else:
            ds_time=ds_time*2*random.uniform(0, 1)





