def bytesFromList(l): # Do we need this one?
    return bytes(l)

def intToTpm(val, valLen):
    v = int(val)
    return v.to_bytes(valLen, 'big')

def intFromTpm(buf, pos, valLen):
    return int.from_bytes(buf[pos : pos + valLen], 'big')