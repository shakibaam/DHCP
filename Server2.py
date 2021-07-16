import json
import struct
import threading
import socket
import time
import random
from OuiLookup import OuiLookup
from concurrent.futures import ThreadPoolExecutor


class Server():

    def __init__(self):
        print('Initializing DHCP Server')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', 67))
        self.connected_clients_list = dict()

        self.OccupyIP = []
        self.waitIP = []
        self.Serviced_ClientsInfo_print = []
        self.client_ips = dict()
        self.reserved = dict()
        self.leaseThreads = dict()

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

    def handle_client(self, xid, mac, addrss, server):

        if mac not in self.client_ips:
            macUpper = str(mac).upper()
            block = self.block_or_not(macUpper)
            reserve = self.reserved_or_not(macUpper)


            if block:
                print("This client is blocked")
                string = "You are blocked "
                self.sock.sendto(string.encode(), ('255.255.255.255', 68))
            if reserve:
                reserved_ip = self.reserved[macUpper]
                print("This client is reserved with ip {}".format(reserved_ip))
                string = "You are reserved with ip {}".format(reserved_ip)
                self.sock.sendto(string.encode(), ('255.255.255.255', 68))
                PCName = OuiLookup().query(mac)
                client_info = [PCName, mac, reserved_ip, "infinity"]
                self.Serviced_ClientsInfo_print.append(client_info)

            if not block and not reserve:
                if mac not in self.connected_clients_list:
                    self.connected_clients_list[mac] = xid

                occupy_ip_len = len(self.OccupyIP)
                all_ip_number = self.stopInterval - self.startInterval + 1
                if occupy_ip_len == all_ip_number:
                    string = "sorry all ips are occupied"
                    self.sock.sendto(string.encode(), ('255.255.255.255', 68))
                else:
                    flag = True

                    offer_ip = ""
                    while (flag):

                        offer = random.randint(self.startInterval, self.stopInterval)
                        offer_ip = self.long2ip(offer)

                        if offer_ip in self.OccupyIP :
                            continue
                        else:
                            print("Server want offer {}".format(offer_ip))
                            self.waitIP.append(offer_ip)

                            flag = False

                    pkt = self.buildPacket_offer(offer_ip, xid, mac)
                    self.sock.sendto(pkt, ('255.255.255.255', 68))
                    msg, client = server.recvfrom(1024)

                    print(self.packet_type(msg))
                    id, chaddrss = self.parse_packet_server(msg)

                    pkt = self.buildPacket_Ack(offer_ip, xid, mac)
                    # start lease time timer

                    self.sock.sendto(pkt, ('255.255.255.255', 68))
                    lease_time = self.lease_time
                    PCName = OuiLookup().query(mac)
                    client_info = [PCName, mac, offer_ip, lease_time]
                    self.Serviced_ClientsInfo_print.append(client_info)
                    index = self.Serviced_ClientsInfo_print.index(client_info)
                    self.OccupyIP.append(offer_ip)
                    self.client_ips[mac] = offer_ip
                    lease_thread = threading.Thread(target=self.lease, args=(mac, offer_ip, xid, index))
                    self.leaseThreads[mac] = lease_thread
                    lease_thread.start()



        else:
            prev_ip = self.client_ips[mac]
            prev_thread = self.leaseThreads[mac]
            print("You are in list yet with {} ,lease time renew".format(prev_ip))
            string = "You are in list yet with {} ,lease time renew".format(prev_ip)
            self.sock.sendto(string.encode(), ('255.255.255.255', 68))
            index = -1
            prev_thread.join()
            self.leaseThreads.pop(mac)
            lease_thread = threading.Thread(target=self.lease, args=(mac, prev_ip, xid, index))
            self.leaseThreads[mac] = lease_thread
            lease_thread.start()

        # show_clients = input("If you want to see clients info type show_clients")
        # if show_clients == "show_clients":
        #     for i in self.Serviced_ClientsInfo_print:
        #         print(i)
        #         print("====================")
        # else:
        #     print("Maybe show you later")

    def get_discovery(self):
        workers = 5

        executor = ThreadPoolExecutor(max_workers=workers)

        while True:
            msg, client = self.sock.recvfrom(1024)

            msg_type = self.packet_type(msg)
            print(msg_type)
            if "DHCPDISCOVER" in msg_type:
                client_xid, client_mac = self.parse_packet_server(msg)
                print("Client xid {}".format(client_xid))
                server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", 67))

                executor.submit(self.handle_client, client_xid, client_mac, client, server)

    def packet_type(self, packet):
        if packet[len(packet) - 1] == 1:
            return "DHCPDISCOVER"
        if packet[len(packet) - 1] == 3:
            return "DHCPREQUEST"

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

        xid_hex = hex(xid).split('x')[-1]

        packet += bytearray.fromhex(xid_hex)  # Transaction ID

        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0

        mac = str(mac).replace(':', '')
        packet += bytearray.fromhex(mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00' * 67  # Server host name
        packet += b'\x00' * 125  # Boot file name
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

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

        packet += bytes.fromhex(xid_hex)  # Transaction ID

        packet += b'\x00\x00'  # Seconds elapsed: 0
        packet += b'\x00\x00'  # Bootp flags
        packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
        packet += ip_as_bytes  # Your (client) IP address: 0.0.0.0
        packet += serverip  # Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0

        mac = str(mac).replace(':', '')
        packet += bytes.fromhex(mac)
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        packet += b'\x00' * 67  # Server host name
        packet += b'\x00' * 125  # Boot file name
        packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP

        packet += b'\x35\x01\x05'

        return packet

    def parse_packet_server(self, pkt):
        xid = int(pkt[4:8].hex(), 16)

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

        if str(mac) in self.reserved:
            reserved = True
        return reserved

    def lease(self, mac, ip, xid, index):
        timeOut = self.lease_time
        print("lease start for {}".format(mac))

        while timeOut:
            if mac not in self.client_ips or ip not in self.OccupyIP or mac not in self.connected_clients_list :
                self.client_ips[mac] = ip
                self.OccupyIP.append(ip)
                self.connected_clients_list[mac] = xid
            mins, secs = divmod(timeOut, 60)
            timer = '{:02d}:{:02d}'.format(mins, secs)

            time.sleep(1)
            timeOut -= 1
            self.Serviced_ClientsInfo_print[index][3] = timeOut

        print("lease expire for {}".format(mac))
        self.OccupyIP.remove(ip)

        self.connected_clients_list.pop(mac)
        self.client_ips.pop(mac)


if __name__ == '__main__':
    b = Server()

    b.get_discovery()
