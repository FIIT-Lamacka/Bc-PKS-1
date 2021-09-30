from scapy.compat import bytes_hex
from scapy.all import rdpcap
import os


class Frame:
    def __init__(self, source_mac, dest_mac, length):
        self.source_mac = source_mac
        self.dest_mac = dest_mac
        self.length = length
        self.raw = None
        self.data = None


class FrameEth2(Frame):
    def __init__(self, source_mac, dest_mac, length, eth_type):
        super().__init__(source_mac, dest_mac, length)
        self.eth_type = eth_type

    def print_info(self):
        print("Destination adress: " + self.dest_mac.upper())
        print("Source adress: " + self.source_mac.upper())
        print("Frame type: Ethernet II")
        print("EtherType: 0x" + self.eth_type)
        medium_l = str(64) if self.length + 4 < 64 else str(self.length+4)
        print("Frame length: " + str(self.length) + "; Length in medium: " + medium_l)

        upper = self.raw.upper()
        data = ""
        for x in range(len(upper)):
            data += chr(upper[x])
            if (x+1) % 2 == 0:
                data += " "
            if (x+1) % 16 == 0:
                data += "  "
            if (x+1) % 32 == 0 and x != 0:
                data += "\n"
        print(data)


class FrameIEEE(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)


class FrameLLC(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)


class FrameRAW(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)


def get_byte(hex_string, pos):
    pos *= 2
    return chr(hex_string[pos]) + chr(hex_string[pos+1])


def extract_destination(hex_string):
    string = ""
    for i in range(6):
        string += get_byte(hex_string, i)
        if i != 5:
            string += ":"

    return string


def extract_source(hex_string):
    string = ""
    for i in range(7, 12):
        string += get_byte(hex_string, i)
        if i != 11:
            string += ":"

    return string


def extract_typelenght(hex_string):
    return get_byte(hex_string, 12) + get_byte(hex_string, 13)


def load_pcap():
    files = os.listdir("to_translate")
    pcap_packets = []
    for name in files:
        pcap_packets.extend(rdpcap("to_translate/" + name))

    raw_packets = []
    for to_string in pcap_packets:
        raw_packets.append(bytes_hex(to_string))

    return raw_packets


def create_frame(packet):
    dest_mac = extract_destination(packet)
    source_mac = extract_source(packet)
    typelen = extract_typelenght(packet)
    length = int(len(packet)/2)

    if int(typelen, 16) > 0x600:
        new_frame_object = FrameEth2(source_mac, dest_mac, length, typelen)
        new_frame_object.data = packet[28:]
        new_frame_object.raw = packet

        return new_frame_object


if __name__ == '__main__':
    packets = load_pcap()
    new_packet = create_frame(packets[0])
    new_packet.print_info()
