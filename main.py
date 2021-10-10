from pks_functions import *


if __name__ == '__main__':
    packets = load_pcap()

    processed_packets = []

    i = 1
    for packet in packets:
        processed_packets.append(create_frame(packet, i))
        i += 1

    for packet in processed_packets:
        packet.print_info()

    ipv4_histogram(processed_packets)

    ''' for x in range(10):
        print("Frame number: " + x)
        processed_packets[x].print_info()
    '''

    '''found = []
    for packet in processed_packets:
        if isinstance(packet, FrameRAW):
            found.append(packet)

    print(len(found))'''