import sys
import socket
import struct
from helpers import getName

# Codes determined using "RFC 1035 Section 3.2.2 Type Values"
# Source: https://datatracker.ietf.org/doc/html/rfc1035
types = {
    'A': 1,
    'NS': 2,
    'MD': 3,
    'MF': 4,
    'CNAME': 5,
    'SOA': 6,
    'MB': 7,
    'MG': 8,
    'NULL': 10,
    'WKS': 11,
    'PTR': 12,
    'HINFO': 13,
    'MINFO': 14,
    'MX': 15,
    'TXT': 16
}
qclass = {
    'IN': 1,
    'CS': 2,
    'CH': 3,
    'HS': 4,
}

opcodeTypes = {
    0: "QUERY",
    1: "IQUERY",
    2: "STATUS"
}

rcodeTypes = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

invertedTypes = {v: k for k, v in types.items()}

invertedClasses = {v: k for k, v in qclass.items()}

def createQuery(queryType):

    # The header contains the following fields:

    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    header_id = 0xABCE # Make this random

    qr = 0
    opcode = 0
    aa = 0
    tc = 0
    rd = 0
    ra = 0
    z = 0
    rcode = 0

    header_flags = (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) | (ra << 7) | (z << 4) | rcode

    qdCount = 1
    anCount = 0
    nsCount = 0
    arCount = 0

    # Pack data into bytes, !HHHHHH, as we have 2 bytes for each part of the header, and 6
    # parts of the header.
    headerData = struct.pack('!HHHHHH',header_id, header_flags, qdCount, anCount, nsCount, arCount)

    # Question section of query.
    #                                 1  1  1  1  1  1
    #   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                                               |
    # /                     QNAME                     /
    # /                                               /
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QTYPE                     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                     QCLASS                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    labels = name.split('.')

    qname = b'' # Required to be byte literal like data from struct.pack

    for label in labels:
        length = len(label)

        qname += struct.pack('!B', length) + label.encode()

    qname += b'\x00'

    qtype = types[queryType]

    qclassInfo = qclass['IN']

    question = qname + struct.pack("!HH", qtype, qclassInfo)

    query = headerData + question

    return query

def parseQuestion(response):
    index = 0

    #Initial index response[0] will have the length
    # of the label as specified by RDC 1035, so we can skip
    # over the question data by adding the length + 1.

    while response[index] != 0:
        index += response[index] + 1

    return index + 1 # index is at null byte.

def parseNameSection(response):
    nameSize = 0

    # The compression scheme allows a domain name in a message to be
    # represented as either:

    #      - a sequence of labels ending in a zero octet - Case 1

    #    - a pointer - Case 2

    #    - a sequence of labels ending with a pointer - Case 3
    while True:
        currByte = response[nameSize]
        nameSize += 1
        if(currByte == 0):
            break # Null terminator reached (Case 1)
        elif currByte & 0xC0 == 0xC0:
            nameSize += 1 # Pointer is 2 octet.
            break # Found pointer at end of name section (Case 2 or 3)

        nameSize += currByte # If not, must be sequence label length
    return nameSize
def parseAnswer(response):

    index = parseNameSection(response) # Skip over name section

    ansType, ansClass, ansTTL, ansRdlength = struct.unpack('!HHLH', response[index:12])

    rData = struct.unpack('!' + 'B'*ansRdlength, response[12: 12 + ansRdlength])

    index = 12 + ansRdlength

    if invertedTypes[ansType] == 'A':
        answer = list(rData)
        answer = [str(item) for item in answer]
        answer = '.'.join(answer)
    else:
        answer = getName(response[12: 12 + ansRdlength], modifiedMessage) # If not ip, decode as domain name.

    print(f"{name}\t{ansTTL}\t{invertedClasses[ansClass]}\t{invertedTypes[ansType]}\t{answer}")

    return index

def separateFlags(flags):

    # Reference for how query flags were encoded.
    # header_flags = (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) | (ra << 7) | (z << 4) | rcode

    rcode = flags & 0xF

    z = (flags >> 4) & 0x7

    ra = (flags >> 7) & 0x1

    rd = (flags >> 8) & 0x1

    tc = (flags >> 9) & 0x1

    aa = (flags >> 10) & 0x1

    opCode = (flags >> 11) & 0xF

    qr = (flags >> 15) & 0x1

    flagsSeparated = {
        "rcode": rcode,
        "z": z,
        "ra": ra,
        "rd": rd,
        "tc": tc,
        "aa": aa,
        "opcode": opCode,
        "qr": qr,
    }

    return flagsSeparated

def parseResponse(response):
    print("Got Answer:")

    byteHeader = response[0:12] # First 12 bytes are the header as specified by RFC 1035.

    unpackedHeader = struct.unpack('!HHHHHH', byteHeader) # Get header

    queryId = unpackedHeader[0]

    flags = separateFlags(unpackedHeader[1])

    opCode = opcodeTypes[flags["opcode"]]

    rCode = rcodeTypes[flags["rcode"]]

    print(f"->>HEADER<<- opcode: {opCode}, status: {rCode}, id: {queryId}")

    flags.pop("opcode")
    flags.pop("rcode")

    usedFlags =  {k:v for (k,v) in flags.items() if v == 1}

    enabledFlags = ' '.join(usedFlags.keys())

    qCount, ansCount, nsCount, arCount = unpackedHeader[2:] # Pos 0 is ID, Pos 1 is Flags, Pos 2-5 is counts

    print(f"flags: {enabledFlags}; QUERY: {qCount}, ANSWER: {ansCount}, AUTHORITY: {nsCount}, ADDITIONAL: {arCount}")
    answerIndex = 0

    print("QUESTION SECTION:")
    for count in range(0, qCount):
        answerIndex = parseQuestion(response[(12 + answerIndex):])

        qType = struct.unpack("!H", response[12 + answerIndex: 14 + answerIndex])[0] # answerIndex + 12 starts at qtype,

        qClassData = struct.unpack("!H", response[14 + answerIndex: 16 + answerIndex])[0] ## answerIndex + 14 starts at qclass

        answerIndex += 4 # Got data from 4 bytes containing qtype and qclass.

        print(f"{name}.\t\t{invertedClasses[qClassData]}\t{invertedTypes[qType]}")

    answerIndex += 12

    print("\nANSWER SECTION:")

    for count in range(0, ansCount):
        # Have to update answer index here
        answerIndex += parseAnswer(response[answerIndex:])

    print("AUTHORITY SECTION:")
    for count in range(0, nsCount):
        answerIndex += parseAnswer(response[answerIndex:])
    return

def printResponse(response):
    print("Got Answer:")
    data = parseResponse(response)

    print(f"->>HEADER<<- opcode: {opCode}, status: {rCode}, id: {queryId}")

    print(f"flags: {enabledFlags}; QUERY: {qCount}, ANSWER: {ansCount}, AUTHORITY: {nsCount}, ADDITIONAL: {arCount}")

    print("QUESTION SECTION:")
    for count in range(0, qCount):
        print(f"{name}.\t\t{invertedClasses[qClassData]}\t{invertedTypes[qType]}")

    print("\nANSWER SECTION:")
    for count in range(0, ansCount):
        print(f"{name}\t{ansTTL}\t{invertedClasses[ansClass]}\t{invertedTypes[ansType]}\t{answer}")


if len(sys.argv) < 5:
    print("Error: invalid arguments\nUsage: python3 Client.py [resolver_ip] [resolver_port] [name] [type]", file=sys.stderr)
    sys.exit()

resolverIP = sys.argv[1]

resolverPort = sys.argv[2]

name = sys.argv[3]

queryTypeArg = sys.argv[4].upper()

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# UDP is connectionless so no connecting to server like with TCP.
client.sendto(createQuery(queryTypeArg), (resolverIP, int(resolverPort)))

modifiedMessage, serverAddress = client.recvfrom(2048)

parseResponse(modifiedMessage)

client.close()



























