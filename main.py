from pks_functions import *


if __name__ == '__main__':
    processed_packets = None



    while True:
        print(Fore.GREEN + "INPUT 'help' FOR LIST OF COMMANDS" + Style.RESET_ALL)
        command = input("> ")
        command.lower()

        if command == "load" or command == "l":
            processed_packets = analyze()

        elif command == "communications" or command == "c":
            if processed_packets is None:
                print(Fore.RED + "No .pcap file parsed yet! Use command \"load\" to parse pcap files!" + Style.RESET_ALL)
                continue
            print("Communications of which protocol would you like to analyze?\n"
                  " 1. HTTP \n 2. HTTPS \n 3. TELNET \n 4. SSH \n 5. FTP Control \n 6. FTP Data \n 7. TFTP \n 8. ICMP "
                  "\n 9. ARP  ")
            to_anal = input("> ")



        elif command == "print" or command == "p":
            if processed_packets is None:
                print(Fore.RED + "No .pcap file parsed yet! Use command \"load\" to parse pcap files!" + Style.RESET_ALL)
                continue
            print_packets(processed_packets)

        elif command == "print -s" or command == "ps":
            if processed_packets is None:
                print(Fore.RED + "No .pcap file parsed yet! Use command \"load\" to parse pcap files!" + Style.RESET_ALL)
                continue
            no = input("Which packet to analyze <1-" + str(len(processed_packets)) + ">?\n")
            try:
                processed_packets[int(no)-1].print_info()
            except IndexError:
                print(Fore.RED + "Unknown value entered!" + Style.RESET_ALL)
            except ValueError:
                print(Fore.RED + "Unknown value entered!" + Style.RESET_ALL)

        elif command == "histogram" or command == "hist" or command == "hi":
            if processed_packets is None:
                print(Fore.RED + "No .pcap file parsed yet! Use command \"load\" to parse pcap files!" + Style.RESET_ALL)
                continue
            ipv4_histogram(processed_packets)
        else:
            print(Fore.RED + "Unknown command!" + Style.RESET_ALL)




