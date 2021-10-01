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
        print("==================================================\n\n")


class FrameSNAP(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)
        self.dsap = None
        self.ssap = None
        self.control = None
        self.vendor_code = None
        self.ethertype = None


class FrameLLC(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)
        self.dsap = None
        self.ssap = None
        self.control = None


class FrameRAW(Frame):
    def __init__(self, source_mac, dest_mac, length):
        super().__init__(source_mac, dest_mac, length)
        self.ipx_header = None


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


def extract_dsap(hex_string):
    return get_byte(hex_string, 14)


def extract_ssap(hex_string):
    return get_byte(hex_string, 15)


def extract_control(hex_string):
    return get_byte(hex_string, 16)


def extract_vendor(hex_string):
    return get_byte(hex_string, 17) + get_byte(hex_string, 18) + get_byte(hex_string, 19)


def extract_802_ethertype(hex_string):
    return get_byte(hex_string, 20) + get_byte(hex_string, 21)


def extract_ipxheader(hex_string):
    return get_byte(hex_string, 14) + get_byte(hex_string, 15) + get_byte(hex_string, 16)


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
    else:
        diff = get_byte(packet, 14) + get_byte(packet, 15)
        if int(diff, 16) == 0xAAAA:
            new_frame_object = FrameSNAP(source_mac, dest_mac, length)
            new_frame_object.data = packet[44:]
            new_frame_object.raw = packet
            new_frame_object.dsap = extract_dsap(packet)
            new_frame_object.ssap = extract_ssap(packet)
            new_frame_object.control = extract_control(packet)
            new_frame_object.vendor_code = extract_vendor(packet)
            new_frame_object.ethertype = extract_802_ethertype(packet)
            return new_frame_object

        elif int(diff, 16) == 0xFFFF:
            new_frame_object = FrameRAW(source_mac, dest_mac, length)
            new_frame_object.data = packet[34:]
            new_frame_object.raw = packet
            new_frame_object.ipx_header = extract_ipxheader(packet)
            return new_frame_object

        else:
            new_frame_object = FrameLLC(source_mac, dest_mac, length)
            new_frame_object.data = packet[34:]
            new_frame_object.raw = packet
            new_frame_object.dsap = extract_dsap(packet)
            new_frame_object.ssap = extract_ssap(packet)
            new_frame_object.control = extract_control(packet)
            return new_frame_object

if __name__ == '__main__':
    packets = load_pcap()

    processed_packets = []
    for packet in packets:
        processed_packets.append(create_frame(packet))

    #for x in range(10):
        #processed_packets[0].print_info()


    found = []
    for packet in processed_packets:
        if isinstance(packet, FrameEth2):
            found.append(packet)

    print(len(found))

