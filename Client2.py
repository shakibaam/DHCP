import ipaddress
import random
import socket
import struct
import sys
from random import randint
from time import *
import threading
import math

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 68))
Mac = ""
XID = ""
BACKOFF_CUTOFF = 120
INITIAL_INTERVAL = 10
dis_time = 10
expire = False


def buildPacket_discovery(mac):
    mac = str(mac).replace(":", "")
    mac = bytes.fromhex(mac)
    global Mac, XID

    Mac = mac
    print(Mac)
    transactionID = b''

    for i in range(4):
        t = randint(0, 255)
        transactionID += struct.pack('!B', t)
    XID = transactionID

    packet = b''
    packet += b'\x01'  # Message type: Boot Request (1)
    packet += b'\x01'  # Hardware type: Ethernet
    packet += b'\x06'  # Hardware address length: 6
    packet += b'\x00'  # Hops: 0
    packet += transactionID  # Transaction ID
    packet += b'\x00\x00'  # Seconds elapsed: 0
    packet += b'\x80\x00'  # Bootp flags:
    packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
    packet += mac

    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    packet += b'\x00' * 67  # Server host name
    packet += b'\x00' * 125  # Boot file nam
    packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    # DHCP IP Address
    packet += b'\x35\x01\x01'

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
    yiaddr_bytes = pkt[16:20]
    yiaddr_original = ipaddress.IPv4Address(yiaddr_bytes)
    siaddr_bytes = pkt[20:24]
    siaddr_original = ipaddress.IPv4Address(siaddr_bytes)
    mac_byte = pkt[28:34]
    mac_original = mac_byte.hex(":")

    return yiaddr_original, siaddr_original, mac_original


def start_process(mac):
    print("Start Process")
    global dis_time

    sock.sendto(buildPacket_discovery(mac), ('<broadcast>', 67))
    get_ip = False
    getAck = False
    finish = False

    msg, b = sock.recvfrom(1024)

    try:
        data = msg.decode('utf-8')
        print(data)
        if "renew" in data:
            getAck = True
            get_ip = True
            timer_thread = threading.Thread(target=lease_expire())
            timer_thread.start()
        elif "blocked" or "reserved" in data:
            finish = True
            quit()

    except (UnicodeDecodeError, AttributeError):
        print(pkt_type(msg))
        offerip, serverip, mac = parse_packet_client(msg)

        print(offerip)

        sock.sendto(buildPacket_request(serverip, offerip), (str(serverip), 67))
        print("send request")
        getAck = False
        sock.settimeout(2)
        try:
            msg, b = sock.recvfrom(1024)
            if msg:
                print("Ack {}".format(msg))
                getAck = True
        except socket.timeout:
            print("Time out ...")

        if getAck == False:
            print("time out!!")

        else:
            print("No time out :)")
            get_ip = True
            timer_thread = threading.Thread(target=lease_expire())
            timer_thread.start()

    return getAck, get_ip, finish


def discovery_timer(initial_interval):
    global dis_time
    dis_time = initial_interval

    while dis_time:
        mins, secs = divmod(dis_time, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        # print(timer)
        sleep(1)
        dis_time -= 1


def lease_expire():
    print("expire timer begin")
    global expire
    lease = 11

    while lease > 0:
        mins, secs = divmod(lease, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer)
        sleep(1)
        lease -= 1
    expire = True


if __name__ == '__main__':

    def discovery_timer(initial_interval):
        print("discovery timer begin")

        global dis_time
        dis_time = initial_interval

        while dis_time:
            mins, secs = divmod(dis_time, 60)
            timer = '{:02d}:{:02d}'.format(mins, secs)
            # print(timer)
            sleep(1)
            dis_time -= 1


    mac = input("Enter your mac address")

    offer_ip = ""
    flag = True
    getAck = False
    getIp = False

    prv_dis = INITIAL_INTERVAL
    while True:
        timer_thread = threading.Thread(target=discovery_timer, args=(dis_time,))
        timer_thread.start()

        while dis_time > 0:
            while not getAck:
                getAck, getIp, finish = start_process(mac)

                if finish:
                    sys.exit()
            # timer_thread = threading.Thread(target=lease_expire())
            # timer_thread.start()

        if dis_time <= 0:
            rand = random.uniform(1, 200) / 200
            print(rand)
            print("Discovery timer finish..Go to begin timer again")
            if getAck == False:
                print("Get ip Not OK..Try again")
                if prv_dis >= BACKOFF_CUTOFF:
                    dis_time = BACKOFF_CUTOFF
                    print("Next discovery time {}".format(dis_time))
                else:
                    generate = prv_dis * 2 * rand
                    print(generate)
                    dis_time = math.floor(generate)
                    print("Next discovery time {}".format(dis_time))
                    prv_dis = dis_time

            elif getIp == True:
                if expire == True:
                    print("IP expired")
                    expire = False
                    if prv_dis >= BACKOFF_CUTOFF:
                        dis_time = BACKOFF_CUTOFF
                        print("Next discovery time {}".format(dis_time))
                    else:
                        generate = prv_dis * 2 * rand
                        print(generate)
                        dis_time = math.floor(generate)
                        print("Next discovery time {}".format(dis_time))
                        prv_dis = dis_time
                else:
                    while expire == False:
                        pass
                        # print("wait for IP to expire")
                    expire = False
                    if prv_dis >= BACKOFF_CUTOFF:
                        dis_time = BACKOFF_CUTOFF
                        print("Next discovery time {}".format(dis_time))
                    else:
                        generate = prv_dis * 2 * rand
                        print(generate)
                        dis_time = math.floor(generate)
                        print("Next discovery time {}".format(dis_time))
                        prv_dis = dis_time

        getIp = False
        getAck = False
           