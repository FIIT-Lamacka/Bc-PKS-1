from pks_frame_classes import *
from scapy.compat import bytes_hex
from scapy.all import rdpcap
import os


# GET BYTE FROM HEXADECIMAL STRING ON POSITION
def get_byte(hex_string, pos):
    pos *= 2
    return chr(hex_string[pos]) + chr(hex_string[pos + 1])


# EXTRACT DESTINATION MAC ADRESS FROM PACKET
def extract_destination(hex_string):
    string = ""
    for i in range(6):
        string += get_byte(hex_string, i)
        if i != 5:
            string += ":"

    return string


# EXTRACT SOURCE MAC DESTINATION FROM PACKET
def extract_source(hex_string):
    string = ""
    for i in range(6, 12):
        string += get_byte(hex_string, i)
        if i != 11:
            string += ":"

    return string


# EXTRACT TYPE OR LENGTH FIELD FROM IEEE OR ETHERNET PACKETS
def extract_typelenght(hex_string):
    return get_byte(hex_string, 12) + get_byte(hex_string, 13)


# EXTRACT DSAP FIELD FROM IEEE PACKETS
def extract_dsap(hex_string):
    return get_byte(hex_string, 14)


# EXTRACT SSAP FIELD FROM IEEE PACKETS
def extract_ssap(hex_string):
    return get_byte(hex_string, 15)


# EXTRACT CONTROL FIELD FROM IEEE PACKETS
def extract_control(hex_string):
    return get_byte(hex_string, 16)


# EXTRACT VENDOR FIELD FROM IEEE LCC PACKETS
def extract_vendor(hex_string):
    return get_byte(hex_string, 17) + get_byte(hex_string, 18) + get_byte(hex_string, 19)


# EXTRACT ETHERTYPE FROM IEEE LLC PACKETS
def extract_802_ethertype(hex_string):
    return get_byte(hex_string, 20) + get_byte(hex_string, 21)


# EXTRACT
def extract_ipxheader(hex_string):
    return get_byte(hex_string, 14) + get_byte(hex_string, 15) + get_byte(hex_string, 16)


# LOAD ALL PACKETS FROM FILES IN "to_translate" DIRECTORY
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


# PRINT ALL GLOBAL PACKETS
def print_packets(packets):
    for packet in packets:
        packet.print_info()


# CREATE USABLE FRAME OBJECTS FROM RAW PCAP PACKETS
def analyze():
    packets = load_pcap()

    processed_packets = []

    i = 1
    for packet in packets:
        processed_packets.append(create_frame(packet, i))
        i += 1

    return processed_packets


# READ HEXADECIMAL DATA STRING FOR A CERTAIN LENGTH FROM A STATED POSITION
def read_hex(data, start, length):
    stop = start + length
    return data[start:stop]


# CONVERT HEXADECIMAL STRING TO A READABLE IP ADRESS
def hex_to_ipv4(data):
    return str(int(data[0:2], 16)) + "." + \
           str(int(data[2:4], 16)) + "." + \
           str(int(data[4:6], 16)) + "." + \
           str(int(data[6:8], 16))


# SORT COMMUNICATIONS BY PORTS AND IP ADRESSES INTO GROUPS OF MATCHING COMMUNICATIONS
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


# FIND TFTP COMMUNICATIONS IN UDP PACKET, SORT TFTP INTO LIST OF LEAD 69 PORTS AND ANSWERS
def tftp_find(udp_packets):
    lead = []
    for packet in udp_packets:
        # MOZE ROBIT BORDEL IDK
        if packet.nested_packet.nested.dest_port == 69 or packet.nested_packet.nested.source_port == 69:
            lead.append(CommunicationUDP(packet))

    for ld in lead:
        for packet in udp_packets:
            if packet.nested_packet.nested.source_port != 69 and packet.nested_packet.nested.dest_port != 69:
                if packet.nested_packet.source_ip == ld.lead.nested_packet.source_ip \
                        or packet.nested_packet.source_ip == ld.lead.nested_packet.dest_ip:
                    if packet.nested_packet.dest_ip == ld.lead.nested_packet.source_ip \
                            or packet.nested_packet.dest_ip == ld.lead.nested_packet.dest_ip:
                        if packet.nested_packet.nested.source_port == ld.lead.nested_packet.nested.source_port \
                                or packet.nested_packet.nested.source_port == ld.lead.nested_packet.nested.dest_port:
                            ld.coms.append(packet)
                        elif packet.nested_packet.nested.dest_port == ld.lead.nested_packet.nested.source_port\
                                or packet.nested_packet.nested.source_port == ld.lead.nested_packet.nested.dest_port:
                            ld.coms.append(packet)

    return lead


# FIND PACKET IN A LIST BY A CERTAIN PORT
def find_packets_by_port(packets, port):
    found_packets = []
    for packet in packets:
        if packet.nested_packet is not None and packet.nested_packet.nested is not None:
            if packet.nested_packet.nested.source_port == port or packet.nested_packet.nested.dest_port == port:
                found_packets.append(packet)

    return found_packets


# PRINT GIVEN COMPLETE AND INCOMPLETE COMMUNICATIONS (UI)
def print_complete_and_incomplete(complete, incomplete):
    if complete is not None:

        print(Fore.CYAN,
              "=====================================\nCOMPLETE COMMUNICATION\n=====================================\n",
              Style.RESET_ALL)
        if len(complete.coms) > 20:
            complete.print_ommited()
        else:
            complete.print_pairs()
    else:
        print(Fore.YELLOW + "Complete communication not found." + Style.RESET_ALL)

    print(Fore.CYAN,
          "=====================================\nINCOMPLETE COMMUNICATION\n=====================================\n",
          Style.RESET_ALL)
    if incomplete is not None:
        if len(incomplete.coms) > 20:
            incomplete.print_ommited()
        else:
            incomplete.print_pairs()
    else:
        print(Fore.YELLOW + "Incomplete communication not found." + Style.RESET_ALL)


# FIND COMMUNICATIONS BY PORT, SORT THEM INTO COMPLETE AND INCOMPLETE AND PRINT THEM
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


# FIND, SORT AND PRINT TFTP COMMUNICATION
def com_tftp(packets):
    udp_packets = []

    for packet in packets:
        if packet.nested_packet is not None and packet.nested_packet.nested is not None and isinstance(
                packet.nested_packet.nested, UDP):
            udp_packets.append(packet)

    com = tftp_find(udp_packets)

    for com in com:
        com.print_ommited()


# FIND AND PRINT ICMP COMMUNICATION
def com_icmp(packets):
    icmp_packets = []
    for packet in packets:
        if packet.nested_packet is not None and packet.nested_packet.nested is not None and isinstance(
                packet.nested_packet.nested, ICMP):
            icmp_packets.append(packet)

    for icmp in icmp_packets:
        icmp.print_info()


# FIND, SORT AND PAIR ARP COMMUNICATION
def com_arp(packets):
    arp_packets = []
    for packet in packets:
        if packet.nested_packet is not None and isinstance(packet.nested_packet, ARP):
            arp_packets.append(packet)

    to_delete = []
    for arp in arp_packets:
        if int(arp.nested_packet.operation, 16) == 1 and arp.nested_packet.spa == arp.nested_packet.tpa:
            to_delete.append(arp)
        if int(arp.nested_packet.operation, 16) == 1 and arp.nested_packet.spa == "0.0.0.0" \
                and (arp.nested_packet.tha == "00:00:00:00:00:00" or arp.nested_packet.tha == "FF:FF:FF:FF:FF:FF"):
            to_delete.append(arp)

    for delete in to_delete:
        arp_packets.remove(delete)

    requests = []
    replies = []
    for arp in arp_packets:
        if int(arp.nested_packet.operation, 16) == 1:
            requests.append(arp)
        elif int(arp.nested_packet.operation, 16) == 2:
            replies.append(arp)

    arp_pairs = []
    for request in requests:
        for reply in replies:
            if request.nested_packet.tpa == reply.nested_packet.spa and \
                    request.nested_packet.spa == reply.nested_packet.tpa and \
                    reply.nested_packet.tha == request.nested_packet.sha and \
                    request.id < reply.id and not reply.nested_packet.has_pair:
                reply.nested_packet.has_pair = True
                request.nested_packet.has_pair = True
                arp_pairs.append(ARPPair(request, reply))

    i = 1
    for arp in arp_pairs:
        print(Fore.GREEN + "===============\n ARP Pair no." + str(i) + "\n===============" + Style.RESET_ALL)
        arp.request.print_info()
        arp.reply.print_info()
        i += 1

    print(Fore.GREEN + "===============\n UNPAIRED \n===============" + Style.RESET_ALL)
    for arp in arp_packets:
        if not arp.nested_packet.has_pair:
            arp.print_info()


# CREATE A TCP OBJECT FROM VALID DATA
def analyze_tcp(data):
    new_frame = TCP()
    new_frame.source_port = int(read_hex(data, 0, 4), 16)
    new_frame.dest_port = int(read_hex(data, 4, 4), 16)
    new_frame.flags = read_hex(data, 25, 3)

    return new_frame


# CREATE AN UDP OBJECT FROM VALID DATA
def analyze_udp(data):
    new_frame = UDP()
    new_frame.source_port = int(read_hex(data, 0, 4), 16)
    new_frame.dest_port = int(read_hex(data, 4, 4), 16)

    return new_frame


# CREATE AN ICMP OBJECT FROM VALID DATA
def analyze_icmp(data):
    new_frame = ICMP()
    new_frame.type = read_hex(data, 0, 2)
    new_frame.code = read_hex(data, 2, 2)

    return new_frame


# CREATE AN IPV4 OBJECT FROM VALID DATA
def analyze_ipv4(data):
    new_packet = PacketIPv4(hex_to_ipv4(read_hex(data, 24, 8)), hex_to_ipv4(read_hex(data, 32, 8)))
    new_packet.raw = data
    header_lenght = int(read_hex(data, 1, 1), 16) * 4

    new_packet.data = data[header_lenght * 2:]
    new_packet.nested_protocol = read_hex(data, 18, 2)
    try:
        new_packet.nested_protocol = config["IPV4_PROTOCOL"][new_packet.nested_protocol.decode("ascii").upper()]

    except KeyError:
        new_packet.nested_protocol = read_hex(data, 18, 2)

    if new_packet.nested_protocol == "TCP":
        new_packet.nested = analyze_tcp(new_packet.data)

    elif new_packet.nested_protocol == "UDP":
        new_packet.nested = analyze_udp(new_packet.data)

    elif new_packet.nested_protocol == "ICMP":
        new_packet.nested = analyze_icmp(new_packet.data)

    return new_packet


# CREATE AN ARP OBJECT FROM VALID DATA
def analyze_arp(data):
    new_packet = ARP()

    new_packet.sha = macify(read_hex(data, 16, 12))
    new_packet.spa = ipify(read_hex(data, 28, 8))
    new_packet.tha = macify(read_hex(data, 36, 12))
    new_packet.tpa = ipify(read_hex(data, 48, 8))
    new_packet.operation = read_hex(data, 12, 4)

    return new_packet


# PRINT A HISTOGRAM OF ALL USED IPS
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


# CREATE AN IEEE OR ETHERNET FRAME FROM VALID DATA
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
        if int(typelen, 16) == 0x806:
            new_frame_object.nested_packet = analyze_arp(new_frame_object.data)

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


# INICIALIZE USER INTERFACE
def init_ui():
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

            if to_anal == "6" or to_anal.upper() == "FTP DATA":
                com_custom(processed_packets, "NO FTP DATA PACKETS", 20)

            if to_anal == "7" or to_anal.upper() == "TFTP":
                com_tftp(processed_packets)

            if to_anal == "8" or to_anal.upper() == "ICMP":
                com_icmp(processed_packets)

            if to_anal == "9" or to_anal.upper() == "ARP":
                com_arp(processed_packets)

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
