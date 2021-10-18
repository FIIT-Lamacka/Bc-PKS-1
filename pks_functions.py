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


def sort_ipport_pairs(packets):

    pairs = []
    unfound = True

    for packet in packets:
        unfound = True
        for com in pairs:
            if com.equals(packet.nested_packet.source_ip, packet.nested_packet.dest_ip,
                            packet.nested_packet.nested.source_port, packet.nested_packet.nested.dest_port):
                com.coms.append(packet)
                unfound = False
                break
        if unfound:
            com = Communication(packet.nested_packet.source_ip, packet.nested_packet.dest_ip,
                                packet.nested_packet.nested.source_port, packet.nested_packet.nested.dest_port)
            com.coms.append(packet)
            pairs.append(com)

    return pairs


def find_packets_by_port(packets,port):
    found_packets = []
    for packet in packets:
        if packet.nested_packet is not None and packet.nested_packet.nested is not None:
            if packet.nested_packet.nested.source_port == port or packet.nested_packet.nested.dest_port == port:
                found_packets.append(packet)

    return found_packets


def print_complete_and_incomplete(complete, incomplete):
    if complete is not None:

        print(Fore.CYAN, "=======================================\nCOMPLETE COMMUNICATION\n=======================================\n", Style.RESET_ALL)
        if len(complete.coms) > 20:
            complete.print_ommited()
        else:
            complete.print_pairs()
    else:
        print(Fore.YELLOW + "Complete communication not found." + Style.RESET_ALL)

    print(Fore.CYAN,
          "=======================================\nINCOMPLETE COMMUNICATION\n=======================================\n",
          Style.RESET_ALL)
    if incomplete is not None:
        if len(incomplete.coms) > 20:
            incomplete.print_ommited()
        else:
            incomplete.print_pairs()
    else:
        print(Fore.YELLOW + "Incomplete communication not found." + Style.RESET_ALL)


def com_custom(packets, error, port):
    http_packets = find_packets_by_port(packets, port)
    if len(http_packets) == 0:
        print(error)
        return

    pairs = sort_ipport_pairs(http_packets)

    complete = None
    incomplete = None
    for pair in pairs:
        if pair.is_complete():
            if complete is None:
                complete = pair
        else:
            if incomplete is None:
                incomplete = pair

    print_complete_and_incomplete(complete, incomplete)


def analyze_tcp(data):
    new_frame = TCP()
    new_frame.source_port = int(read_hex(data, 0, 4),16)
    new_frame.dest_port = int(read_hex(data, 4, 4), 16)
    new_frame.flags = read_hex(data, 25, 3)

    return new_frame


def analyze_ipv4(data):
    new_packet = PacketIPv4(hex_to_ipv4(read_hex(data, 24, 8)), hex_to_ipv4(read_hex(data, 32, 8)))
    new_packet.raw = data
    header_lenght = int(read_hex(data, 1, 1), 16) * 4

    new_packet.data = data[header_lenght*2:]
    new_packet.nested_protocol = read_hex(data, 18, 2)
    try:
        new_packet.nested_protocol = config["IPV4_PROTOCOL"][new_packet.nested_protocol.decode("ascii").upper()]

    except KeyError:
        new_packet.nested_protocol = read_hex(data, 18, 2)

    if new_packet.nested_protocol == "TCP":
        new_packet.nested = analyze_tcp(new_packet.data)

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

def initUI():
    processed_packets = None

    while True:
        print(Fore.GREEN + "INPUT 'help' FOR LIST OF COMMANDS" + Style.RESET_ALL)
        command = input("> ")
        command.lower()

        if command == "load" or command == "l":
            processed_packets = analyze()
            print("All packets have been loaded succesfully!")

        elif command == "communications" or command == "c":
            if processed_packets is None:
                print(
                    Fore.RED + "No .pcap file parsed yet! Use command \"load\" to parse pcap files!" + Style.RESET_ALL)
                continue
            print("Communications of which protocol would you like to analyze?\n"
                  " 1. HTTP \n 2. HTTPS \n 3. TELNET \n 4. SSH \n 5. FTP Control \n 6. FTP Data \n 7. TFTP \n 8. ICMP "
                  "\n 9. ARP  ")
            to_anal = input("> ")

            if to_anal == "1" or to_anal.upper() == "HTTP":
                com_custom(processed_packets, "NO HTTP PACKETS", 80)

            if to_anal == "2" or to_anal.upper() == "HTTPS":
                com_custom(processed_packets, "NO HTTPS PACKETS", 443)

            if to_anal == "3" or to_anal.upper() == "TELNET":
                com_custom(processed_packets, "NO TELNET PACKETS", 23)

            if to_anal == "4" or to_anal.upper() == "SSH":
                com_custom(processed_packets, "NO SSH PACKETS", 22)

            if to_anal == "5" or to_anal.upper() == "FTP CONTROL":
                com_custom(processed_packets, "NO FTP COMMAND PACKETS", 21)



        elif command == "print" or command == "p":
            if processed_packets is None:
                print(
                    Fore.RED + "No .pcap file parsed yet! Use command \"load\" to parse pcap files!" + Style.RESET_ALL)
                continue
            print_packets(processed_packets)

        elif command == "print -s" or command == "ps":
            if processed_packets is None:
                print(
                    Fore.RED + "No .pcap file parsed yet! Use command \"load\" to parse pcap files!" + Style.RESET_ALL)
                continue
            no = input("Which packet to analyze <1-" + str(len(processed_packets)) + ">?\n")
            try:
                processed_packets[int(no) - 1].print_info()
            except IndexError:
                print(Fore.RED + "Unknown value entered!" + Style.RESET_ALL)
            except ValueError:
                print(Fore.RED + "Unknown value entered!" + Style.RESET_ALL)

        elif command == "histogram" or command == "hist" or command == "hi":
            if processed_packets is None:
                print(
                    Fore.RED + "No .pcap file parsed yet! Use command \"load\" to parse pcap files!" + Style.RESET_ALL)
                continue
            ipv4_histogram(processed_packets)
        else:
            print(Fore.RED + "Unknown command!" + Style.RESET_ALL)