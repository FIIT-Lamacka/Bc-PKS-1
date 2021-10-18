from independent_functions import *
import configparser
from colorama import *

config = configparser.ConfigParser()
config.read("config.conf")
init()


class Frame:
    def __init__(self, source_mac, dest_mac, length):
        self.source_mac = source_mac
        self.dest_mac = dest_mac
        self.length = length
        self.raw = None
        self.data = None
        self.id = None
        self.nested_packet = None


class FrameEth2(Frame):
    def __init__(self, source_mac, dest_mac, length, eth_type):
        super().__init__(source_mac, dest_mac, length)
        self.eth_type = eth_type

    def print_info(self):
        print(Fore.GREEN + "Frame number: " + Style.RESET_ALL + str(self.id))
        print("Destination adress: " + self.dest_mac.upper())
        print("Source adress: " + self.source_mac.upper())
        print("Frame type: Ethernet II")
        medium_l = str(64) if self.length + 4 < 64 else str(self.length + 4)
        print("Frame length: " + str(self.length) + "; Length in medium: " + medium_l)
        print("EtherType: 0x" + self.eth_type)
        try:
            print("Nested protocol: " + config["EtherType"][str(self.eth_type).upper()])
        except KeyError:
            print(Back.RED + Fore.BLACK + "Nested protocol: PROTOCOL NOT FOUND" + Style.RESET_ALL)

        if isinstance(self.nested_packet, PacketIPv4):
            print("")
            self.nested_packet.print_info()
            print("")

            if isinstance(self.nested_packet.nested, TCP):
                print("")
                self.nested_packet.nested.print_info()
                print("")




        print(prettify_data(self.raw))
        print("==================================================\n\n")


class FrameSNAP(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)
        self.dsap = None
        self.ssap = None
        self.control = None
        self.vendor_code = None
        self.ethertype = None

    def print_info(self):
        print("Frame number: " + str(self.id))
        print("Destination adress: " + self.dest_mac.upper())
        print("Source adress: " + self.source_mac.upper())
        print("Frame type: IEEE 802.3 SNAP")
        print("Length: " + str(self.length))
        medium_l = str(64) if self.length + 4 < 64 else str(self.length + 4)
        print("Frame length: " + str(self.length) + "; Length in medium: " + medium_l)
        print("DSAP: " + self.dsap + "; SSAP: " + self.ssap + "; Control: " + self.control)
        print("Vendor Code: " + self.vendor_code + "; EtherType: " + self.ethertype)

        print(prettify_data(self.raw))
        print("==================================================\n\n")


class FrameLLC(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)
        self.dsap = None
        self.ssap = None
        self.control = None

    def print_info(self):
        print("Frame number: " + str(self.id))
        print("Destination adress: " + self.dest_mac.upper())
        print("Source adress: " + self.source_mac.upper())
        print("Frame type: IEEE 802.3 LLC")
        print("Length: " + str(self.length))
        medium_l = str(64) if self.length + 4 < 64 else str(self.length + 4)
        print("Frame length: " + str(self.length) + "; Length in medium: " + medium_l)
        print("DSAP: " + self.dsap + "; SSAP: " + self.ssap + "; Control: " + self.control)
        try:
            print("Nested protocol: " + config["LLC_DSAP"][str(self.dsap).upper()])
        except KeyError:
            print("Nested protocol: PROTOCOL NOT FOUND")

        print(prettify_data(self.raw))
        print("==================================================\n\n")


class FrameRAW(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)
        self.ipx_header = None

    def print_info(self):
        print("Frame number: " + str(self.id))
        print("Destination adress: " + self.dest_mac.upper())
        print("Source adress: " + self.source_mac.upper())
        print("Frame type: IEEE 802.3 RAW")
        medium_l = str(64) if self.length + 4 < 64 else str(self.length + 4)
        print("Length: " + str(self.length))
        print("Frame length: " + str(self.length) + "; Length in medium: " + medium_l)
        print("Nested protocol: IPx")

        print(prettify_data(self.raw))
        print("==================================================\n\n")


class PacketIPv4:
    def __init__(self, source_ip, dest_ip):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.header_length = None
        self.total_lenght = None
        self.nested_protocol = None
        self.nested = None
        self.raw = None
        self.data = None

    def print_info(self):
        print("Source IP address: " + self.source_ip)
        print("Destination IP address: " + self.dest_ip)
        if self.nested_protocol is not None:
            print("\nLayer 4 protocol: ", self.nested_protocol)


class TCP:
    def __init__(self):
        self.source_port = None
        self.dest_port = None
        self.flags = None

    def print_info(self):
        print("Source port: ", self.source_port)
        print("Destination port: ", self.dest_port)
        print("Flags: " ,build_tcp_flags(self.flags))


class UDP:
    def __init__(self):
        self.source_port = None
        self.dest_port = None

    def print_info(self):
        print("Source port: ", self.source_port)
        print("Destination port: ", self.dest_port)


class Communication:
    def __init__(self, add1, add2, port1, port2):
        self.add1 = add1
        self.add2 = add2
        self.port1 = port1
        self.port2 = port2
        self.coms = []

    def equals(self, add1, add2, port1, port2):
        if self.add1 == add1 or self.add1 == add2:
            if self.add2 == add1 or self.add2 == add2:
                if self.port1 == port1 or self.port1 == port2:
                    if self.port2 == port1 or self.port2 == port2:
                        return True

        # print("FALSE:" + " " + self.add1 + " "+ self.add2 + " "+ str(self.port1) + " "+ str(self.port2) + " "+ add1
        # + " "+ add2 + " "+ str(port1) + " "+ str(port2))
        return False

    def print_pairs(self):
        for packet in self.coms:
            packet.print_info()


    def print_ommited(self):
        for i in range(10):
            self.coms[i].print_info()

        print(Fore.GREEN + "=================\nOUTPUT SHORTENED\n=================\n")

        for x in range(10):
            i = (len(self.coms)-10) + x
            self.coms[i].print_info()


    def is_complete(self):
        #print(build_tcp_flags(self.coms[0].nested_packet.nested.flags), build_tcp_flags(self.coms[1].nested_packet.nested.flags), build_tcp_flags(self.coms[2].nested_packet.nested.flags), end=" ")

        if len(self.coms) < 3:
            return False

        if "SYN" in build_tcp_flags(self.coms[0].nested_packet.nested.flags) and "SYN" in build_tcp_flags(self.coms[1].nested_packet.nested.flags) and "ACK" in build_tcp_flags(self.coms[1].nested_packet.nested.flags) and "ACK" in build_tcp_flags(self.coms[2].nested_packet.nested.flags):
            com_len = len(self.coms) - 1
            if "ACK" in build_tcp_flags(self.coms[com_len].nested_packet.nested.flags) and "FIN" in build_tcp_flags(
                    self.coms[com_len - 1].nested_packet.nested.flags) and "ACK" in build_tcp_flags(
                    self.coms[com_len - 2].nested_packet.nested.flags) and "FIN" in build_tcp_flags(
                    self.coms[com_len - 3].nested_packet.nested.flags):
                return True
            if "ACK" in build_tcp_flags(self.coms[com_len].nested_packet.nested.flags) and "FIN" in build_tcp_flags(
                self.coms[com_len - 1].nested_packet.nested.flags) and "ACK" in build_tcp_flags(
                self.coms[com_len - 1].nested_packet.nested.flags) and "FIN" in build_tcp_flags(
                self.coms[com_len - 2].nested_packet.nested.flags):
                return True
            if "RST" in build_tcp_flags(self.coms[com_len].nested_packet.nested.flags):
                return True
        print("FALSE")
        return False
