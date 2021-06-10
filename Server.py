import json
import struct
import threading
import socket
import logging
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
        self.clients = []
        self.OccupyIP = []
        self.Serviced_ClientsInfo = dict()
        self.reserved = dict()
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
        if xid not in self.connected_clients_list:
            block = self.block_or_not(mac)
            reserve = self.reserved_or_not(mac)
            print(reserve)
            if block:
                print("This client is blocked")
                string = "You are blocked blocked"
                server.sendto(string.encode(), ('255.255.255.255', 67))
            if reserve:
                reserved_ip = self.reserved[mac]
                print("This client is reserved with ip {}".format(reserved_ip))
                string = "You are reserved with ip {}".format(reserved_ip)
                self.sock.sendto(string.encode(), ('255.255.255.255', 67))

            else:
                self.connected_clients_list[xid] = mac
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
                    pkt = self.buildPacket_offer(offer_ip, xid)
                    self.sock.sendto(pkt, ('255.255.255.255', 67))
                    while True:
                        print("hhello")
                        msg, client = server.recvfrom(1024)
                        print("=======")
                        print("Request coming {}".format(str(msg)))
                        pkt=self.buildPacket_Ack(offer_ip,xid)
                        self.sock.sendto(pkt, ('255.255.255.255', 67))


    def listen_clients(self):
        while True:
            msg, client = self.sock.recvfrom(1024)

            logging.info('Received data from client %s: %s', client, msg)
            msg_type = self.packet_type(msg)
            print(msg_type["dhcp_message_type"])
            if "DHCPDISCOVER" in msg_type["dhcp_message_type"]:
                client_xid, client_mac = self.parse_packet(msg)
                server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", 68))

                t = threading.Thread(target=self.talkToClient, args=(server, client_xid, client_mac, client,))
                # self.connected_clients_list[client_xid]=client_mac
                t.start()

    def packet_type(self, packet):
        pkt = dhcppython.packet.DHCPPacket.from_bytes(packet)

        # print(pkt.options[0].value)
        return pkt.options[0].value

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

    def buildPacket_offer(self, offer_ip, xid):
        ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
        serverip = bytes(map(int, str("127.0.0.1").split('.')))

        packet = b''
        packet += b'\x02'
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0
        # print("xidddd{}".format(xid))
        xid_hex = hex(xid).split('x')[-1]
        print(xid_hex)
        packet += bytearray.fromhex(xid_hex)  # Transaction ID
        # TODO HANDLE ID FOR EACH CLIENT
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        mac = self.connected_clients_list[xid]
        mac = str(mac).replace(':', '')
        packet += bytearray.fromhex(mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x02'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

        return packet

    def buildPacket_Ack(self, offer_ip, xid):
        ip_as_bytes = bytes(map(int, str(offer_ip).split('.')))
        serverip = bytes(map(int, str("127.0.0.1").split('.')))

        packet = b''
        packet += b'\x02'
        packet += b'\x01'  # Hardware type: Ethernet
        packet += b'\x06'  # Hardware address length: 6
        packet += b'\x00'  # Hops: 0

        xid_hex = hex(xid).split('x')[-1]
        print(xid_hex)
        packet += bytearray.fromhex(xid_hex)  # Transaction ID
        # TODO HANDLE ID FOR EACH CLIENT
        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
        # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        mac = self.connected_clients_list[xid]
        mac = str(mac).replace(':', '')
        packet += bytearray.fromhex(mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  # Server host name not given
        packet += b'\x00' * 125  # Boot file name not given
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
        # DHCP IP Address
        packet += b'\x35\x01\x05'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover

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

    def parse_packet(self, pkt):
        #  parse packet in order to get some info about client
        pkt = dhcppython.packet.DHCPPacket.from_bytes(pkt)
        print("client xid is  {}".format(pkt.xid))
        print("client phisycal address is {}".format(pkt.chaddr))
        return pkt.xid, pkt.chaddr

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


if __name__ == '__main__':
    # Make sure all log messages show up
    logging.getLogger().setLevel(logging.DEBUG)

    b = Broker()
    b.listen_clients()
