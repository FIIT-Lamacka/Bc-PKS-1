def prettify_data(hex_string):
    upper = hex_string.upper()
    data = ""
    for x in range(len(upper)):
        data += chr(upper[x])
        if (x + 1) % 2 == 0:
            data += " "
        if (x + 1) % 16 == 0:
            data += "  "
        if (x + 1) % 32 == 0 and x != 0:
            data += "\n"

    return data
