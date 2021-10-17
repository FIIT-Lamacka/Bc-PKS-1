from pks_frame_classes import *
from scapy.compat import bytes_hex
from scapy.all import rdpcap

import os


def get_byte(hex_string, pos):
    pos *= 2
    return chr(hex_string[pos]) + chr(hex_string[pos + 1])


def extract_destination(hex_string):
    string = ""
    for i in range(6):
        string += get_byte(hex_string, i)
        if i != 5:
            string += ":"

    return string


def extract_source(hex_string):
    string = ""
    for i in range(6, 12):
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
    # file loading stackoverflow.com
    files = os.listdir("to_translate")
    pcap_packets = []
    for name in files:
        pcap_packets.extend(rdpcap("to_translate/" + name))

    raw_packets = []
    for to_string in pcap_packets:
        raw_packets.append(bytes_hex(to_string))

    return raw_packets


def print_packets(packets):
    for packet in packets:
        packet.print_info()


def analyze():
    packets = load_pcap()

    processed_packets = []

    i = 1
    for packet in packets:
        processed_packets.append(create_frame(packet, i))
        i += 1

    return processed_packets

def read_hex(data, start, length):
    stop = start + length
    return data[start:stop]


def hex_to_ipv4(data):
    return str(int(data[0:2], 16)) + "." + \
           str(int(data[2:4], 16)) + "." + \
           str(int(data[4:6], 16)) + "." + \
           str(int(data[6:8], 16))


def analyze_ipv4(data):
    new_packet = PacketIPv4(hex_to_ipv4(read_hex(data, 24, 8)), hex_to_ipv4(read_hex(data, 32, 8)))
    new_packet.raw = data
    header_lenght = int(read_hex(data, 1, 1), 16) * 4

    new_packet.data = data[header_lenght*2:]
    new_packet.nested_protocol = read_hex(data, 18, 2)
    print(new_packet.nested_protocol)



    return new_packet


def ipv4_histogram(processed_packets):
    addr = dict()

    for packet in processed_packets:
        if isinstance(packet, FrameEth2) and isinstance(packet.nested_packet, PacketIPv4):
            if packet.nested_packet.source_ip in addr:
                addr[packet.nested_packet.source_ip] += 1
            else:
                addr[packet.nested_packet.source_ip] = 1

    for key in addr.keys():
        print(key)

    most_used = max(addr, key=addr.get)
    print("Most used IPv4 adress: " + most_used + " used " + str(addr[most_used]) + " times.")


def create_frame(packet, frame_id):
    dest_mac = extract_destination(packet)
    source_mac = extract_source(packet)
    typelen = extract_typelenght(packet)
    length = int(len(packet) / 2)

    if int(typelen, 16) > 0x600:
        new_frame_object = FrameEth2(source_mac, dest_mac, length, typelen)
        new_frame_object.data = packet[28:]
        new_frame_object.raw = packet
        new_frame_object.id = frame_id
        if int(typelen, 16) == 0x800:
            new_frame_object.nested_packet = analyze_ipv4(new_frame_object.data)

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
            new_frame_object.id = frame_id

            return new_frame_object

        elif int(diff, 16) == 0xFFFF:
            new_frame_object = FrameRAW(source_mac, dest_mac, length)
            new_frame_object.data = packet[34:]
            new_frame_object.raw = packet
            new_frame_object.ipx_header = extract_ipxheader(packet)
            new_frame_object.id = frame_id

            return new_frame_object

        else:
            new_frame_object = FrameLLC(source_mac, dest_mac, length)
            new_frame_object.data = packet[34:]
            new_frame_object.raw = packet
            new_frame_object.dsap = extract_dsap(packet)
            new_frame_object.ssap = extract_ssap(packet)
            new_frame_object.control = extract_control(packet)
            new_frame_object.id = frame_id

            return new_frame_object
