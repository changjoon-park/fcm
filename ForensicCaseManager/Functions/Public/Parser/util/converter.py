def convertfrom_extended_ascii(string: str, encoding: str):
    char_decimals = []
    for char in string:
        char_decimals.append(ord(char))
    try:
        char_bytes = bytes(char_decimals)
        return char_bytes.decode(encoding)
    except:
        return string