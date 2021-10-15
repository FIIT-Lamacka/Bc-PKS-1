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
