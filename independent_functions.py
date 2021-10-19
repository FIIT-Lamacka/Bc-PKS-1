def prettify_data(hex_string):
    upper = hex_string.upper()
    num = 0x0
    data = "{:04d}".format(num) + "\t"
    for x in range(len(upper)):
        data += chr(upper[x])
        if (x + 1) % 2 == 0:
            data += " "
        if (x + 1) % 16 == 0:
            data += "  "
        if (x + 1) % 32 == 0 and x != 0:
            num += 0x10
            data += "\n" + "{:04d}".format(num) + "\t"
    return data


def build_tcp_flags(flags):
    binary = bin(int(flags, 16))[2:].zfill(8)
    build = "["
    if binary[7] == "1":
        build += "FIN "
    if binary[6] == "1":
        build += "SYN "
    if binary[5] == "1":
        build += "RST "
    if binary[4] == "1":
        build += "PSH "
    if binary[3] == "1":
        build += "ACK "
    if binary[2] == "1":
        build += "URG "
    if binary[1] == "1":
        build += "ECE "
    if binary[0] == "1":
        build += "CWR "

    final = build[0:len(build)-1]
    final += "]"

    return final


def macify(raw):
    clone = raw.decode("utf-8").upper()
    return clone[0:2] + ":" + clone[2:4] + ":" + clone[4:6] + ":" + clone[6:8] + ":" + clone[8:10] + ":" + clone[10:12]


def ipify(raw):
    return str(int(raw[0:2], 16)) + "." + str(int(raw[2:4], 16)) + "." + str(int(raw[4:6], 16)) \
           + "." + str(int(raw[6:8], 16))
