def header_checksum(header, size):
    cksum = 0
    pointer = 0

    while size > 1:
        cksum += int((str("%02x" % (header[pointer],)) +
                      str("%02x" % (header[pointer + 1],))), 16)
        size -= 2
        pointer += 2
    if size: 
        cksum += header[pointer]

    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >> 16)

    return (~cksum) & 0xFFFF

def cs(data):
    data = data.split()
    data = [int(item,16) for item in data]
    return  "%04x" % (header_checksum(data, len(data)),)