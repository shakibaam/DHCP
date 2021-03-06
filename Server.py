import json
import struct
import threading
import socket
import logging
import time

import dhcppython
import random
from uuid import getnode as get_mac


class Broker():

    def __init__(self):
        logging.info('Initializing DHCP Server')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', 68))
        self.connected_clients_list = dict()
        # self.clients = []
        self.OccupyIP = []
        self.Serviced_ClientsInfo_print = []
        self.client_ips = dict()
        self.reserved = dict()
        self.leaseThreads=dict()
        self.startInterval = 0
        self.stopInterval = 0
        self.serverIP = socket.gethostbyname(socket.gethostname())
        f = open("C:\\Users\\Asus\\PycharmProjects\\CN_P3\\configs.json")
        data = json.load(f)
        f.close()
        self.pool_mode = data["pool_mode"]
        self.range_from = data["range"]["from"]
        self.range_to = data["range"]["to"]
        self.subnet_block = data["subnet"]["ip_block"]
        self.subnet_mask = data["subnet"]["subnet_mask"]
        self.lease_time = data["lease_time"]
        if self.pool_mode == "range":
            self.startInterval = self.ip2long(self.range_from)
            self.stopInterval = self.ip2long(self.range_to)
        elif self.pool_mode == "subnet":
            self.startInterval = self.ip2long(self.subnet_block)
            self.stopInterval = self.ip2long(self.subnet_mask)
        if len(data["reservation_list"]) != 0:
            for key in data["reservation_list"]:
                self.reserved[key] = data["reservation_list"][key]
                self.OccupyIP.append(data["reservation_list"][key])

    def talkToClient(self, server, xid, mac, addrss):

        # logging.info("Talk to client %s", ip)
        # new Client arrive
        if mac not in self.client_ips:
            block = self.block_or_not(mac)
            reserve = self.reserved_or_not(mac)

            print(reserve)
            if block:
                print("This client is blocked")
                string = "You are blocked "
                self.sock.sendto(string.encode(), ('255.255.255.255', 67))
            if reserve:
                reserved_ip = self.reserved[mac]
                print("This client is reserved with ip {}".format(reserved_ip))
                string = "You are reserved with ip {}".format(reserved_ip)
                self.sock.sendto(string.encode(), ('255.255.255.255', 67))
                client_info = ["Name", mac, reserved_ip, "infinity"]
                self.Serviced_ClientsInfo_print.append(client_info)

            else:
                if mac not in self.connected_clients_list:
                    self.connected_clients_list[mac] = xid
                # print(self.connected_clients_list)
                occupy_ip_len = len(self.OccupyIP)
                all_ip_number = self.stopInterval - self.startInterval + 1
                if occupy_ip_len == all_ip_number:
                    string = "sorry all ips are occupied"
                    self.sock.sendto(string.encode(), ('255.255.255.255', 67))
                else:
                    flag = True
                    offer = 0
                    offer_ip = ""
                    while (flag):

                        offer = random.randint(self.startInterval, self.stopInterval)
                        offer_ip = self.long2ip(offer)

                        if offer_ip in self.OccupyIP:
                            continue
                        else:
                            print("Server want offer {}".format(offer_ip))

                            flag = False
                    print("lets offer to {}".format(mac))
                    pkt = self.buildPacket_offer(offer_ip, xid, mac)
                    self.sock.sendto(pkt, ('255.255.255.255', 67))

                    msg, client = server.recvfrom(1024)
                    id, chaddrss = self.parse_packet_server(msg)

                    pkt = self.buildPacket_Ack(offer_ip, xid, mac)
                    # start lease time timer
                    self.sock.sendto(pkt, ('255.255.255.255', 67))
                    lease_time = self.lease_time
                    client_info = ["Name", mac, offer_ip, lease_time]
                    self.Serviced_ClientsInfo_print.append(client_info)
                    index = self.Serviced_ClientsInfo_print.index(client_info)
                    self.OccupyIP.append(offer_ip)
                    self.client_ips[mac] = offer_ip
                    lease_thread = threading.Thread(target=self.lease,args=(mac,offer_ip))
                    self.leaseThreads[mac]=lease_thread
                    lease_thread.start()


                    # TODO HANDLE NAME OF COMPUTERS
        else:
            prev_ip=self.client_ips[mac]
            prev_thread=self.leaseThreads[mac]
            print("You are in list yet with {} ,lease time renew".format(prev_ip))
            string = "You are in list yet with {} ,lease time renew".format(prev_ip)
            self.sock.sendto(string.encode(), ('255.255.255.255', 67))
            index=-1
            prev_thread.join()
            self.leaseThreads.pop(mac)
            lease_thread = threading.Thread(target=self.lease, args=(mac,prev_ip))
            self.leaseThreads[mac] = lease_thread
            lease_thread.start()

            # TODO HANDLE NAME OF COMPUTERS




    def listen_clients(self):
        show_client_thread = threading.Thread(target=self.show_clients())
        show_client_thread.start()
        while True:
            msg, client = self.sock.recvfrom(1024)

            logging.info('Received data from client %s: %s', client, msg)
            msg_type = self.packet_type(msg)
            print(msg_type)
            if "DHCPDISCOVER" in msg_type:
                client_xid, client_mac = self.parse_packet_server(msg)
                print("Client xid {}".format(client_xid))
                server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", 68))

                t = threading.Thread(target=self.talkToClient, args=(server, client_xid, client_mac, client,))
                # self.connected_clients_list[client_xid]=client_mac
                t.start()

    def packet_type(self, packet):
        if packet[len(packet) - 1] == 1:
            return "DHCPDISCOVER"
        if packet[len(packet) - 1] == 3:
            return "DHCPREQUEST"
        # pkt = dhcppython.packet.DHCPPacket.from_bytes(packet)

        # print(pkt.options[0].value)
        # return pkt.options[0].value

    def ip2long(self, ip):
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]

    def long2ip(self, data):
        return socket.inet_ntoa(struct.pack('!L', data))

    def isReserved(self, ip):
        Reserved = False
        split = str(ip).split(".")
        if split[len(split) - 1] == "0" or split[len(split) - 1] == "1":
            Reserved = True
        return Reserved

    def buildPacket_offer(self, offer_ip, xid, mac):
        ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
        serverip = bytes(map(int, str("127.0.0.1").split('.')))

        packet = b''
        packet += b'\x02'  # opcode
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        # print("xidddd{}".format(xid))
        xid_hex = hex(xid).split('x')[-1]
        print(xid_hex)
        packet += bytearray.fromhex(xid_hex)  # Transaction ID

        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        # mac = self.connected_clients_list[xid]
        mac = str(mac).replace(':', '')
        packet += bytearray.fromhex(mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00' * 67  # Server host name
        packet += b'\x00' * 125  # Boot file name
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x02'

        return packet

    def buildPacket_Ack(self, offer_ip, xid, mac):
        ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
        serverip = bytes(map(int, str("127.0.0.1").split('.')))

        packet = b''
        packet += b'\x02'
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0

        xid_hex = hex(xid).split('x')[-1]
        print(xid_hex)
        packet += bytes.fromhex(xid_hex)  # Transaction ID

        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        # mac = self.connected_clients_list[xid]
        mac = str(mac).replace(':', '')
        packet += bytes.fromhex(mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00' * 67  # Server host name
        packet += b'\x00' * 125  # Boot file name
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x05'

        return packet

    def getMacInBytes(self):
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

    def parse_packet_server(self, pkt):

        xid = int(pkt[4:8].hex(), 16)
        # print(pkt[28:44])
        mac_byte = pkt[28:34]
        mac_original = mac_byte.hex(":")

        return xid, mac_original

    def block_or_not(self, mac):
        block = False
        f = open("C:\\Users\\Asus\\PycharmProjects\\CN_P3\\configs.json")
        data = json.load(f)
        f.close()
        if mac in data["black_list"]:
            block = True
        return block

    def reserved_or_not(self, mac):
        reserved = False
        print(self.reserved)
        print(mac)
        if str(mac) in self.reserved:
            reserved = True
        return reserved

    def show_clients(self):
        pass
        # while True:
        #         show=input()
        #         if show=="show_clients":
        #             print(self.Serviced_ClientsInfo_print)
        #
        #

    def lease(self,mac,ip):
        timeOut=self.lease_time
        print("lease start for {}".format(mac))

        while timeOut:
            mins, secs = divmod(timeOut, 60)
            timer = '{:02d}:{:02d}'.format(mins, secs)
            # print(timer)
            time.sleep(1)
            timeOut -= 1
        print("lease expire for {}".format(mac))
        self.OccupyIP.remove(ip)
        self.connected_clients_list.pop(str(mac))
        self.client_ips.pop(str(mac))


if __name__ == '__main__':
    # Make sure all log messages show up
    logging.getLogger().setLevel(logging.DEBUG)

    b = Broker()
    b.listen_clients()
