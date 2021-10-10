from independent_functions import *
import configparser


config = configparser.ConfigParser()
config.read("config.conf")


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
        print("Frame number: " + str(self.id))
        print("Destination adress: " + self.dest_mac.upper())
        print("Source adress: " + self.source_mac.upper())
        print("Frame type: Ethernet II")
        print("EtherType: 0x" + self.eth_type)
        medium_l = str(64) if self.length + 4 < 64 else str(self.length+4)
        print("Frame length: " + str(self.length) + "; Length in medium: " + medium_l)
        try:
            print("Nested protocol: " + config["EtherType"][str(self.eth_type).upper()])
        except KeyError:
            print("Nested protocol: PROTOCOL NOT FOUND")

        if isinstance(self.nested_packet, PacketIPv4):
            print("")
            self.nested_packet.print_info()

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
        print("Frame type: IEEE 802.2 SNAP")
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
        print("Frame type: IEEE 802.2 LLC")
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
        print("Frame type: IEEE 802.2 RAW")
        medium_l = str(64) if self.length + 4 < 64 else str(self.length+4)
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
        self.raw = None
        self.data = None

    def print_info(self):
        print("Source IP address: " + self.source_ip)
        print("Destination IP address: " + self.dest_ip)
