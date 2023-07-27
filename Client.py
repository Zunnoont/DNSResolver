import sys
import socket
import struct
from helpers import *
import pprint
import time

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
    'TXT': 16,
    'AAAA': 28
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

    if invertedTypes[qtype] == 'PTR':
        qname = encodePTRName(name)

    qclassInfo = qclass['IN']

    question = qname + struct.pack("!HH", qtype, qclassInfo)

    query = headerData + question

    # FORMERR query for testing
    # query = b'\x01\x00\x01\x00\x00\x01\x00\x00\x00\x00\x03www\x06example\x03com\x00\x00\x01\x00\x01'

    return query
def encodePTRName(ipAdresss):
    ipBytes = ipAdresss.split('.')

    ipBytes.reverse()

    name = b''

    for x in ipBytes:
        length = len(x)
        name += struct.pack('!B', length) + x.encode()

    length = len("IN-ADDR")
    name += struct.pack('!B', length) + "IN-ADDR".encode()

    length = len("ARPA")
    name += struct.pack('!B', length) + "ARPA".encode()

    name += b'\x00'

    return name

def printResponse(response):
    pp = pprint.PrettyPrinter(indent=2)

    data = parseResponse(response, True)

    # pp.pprint(data)

    queryId = data['id']

    opCode = data['opcode']

    rCode = data['rcode']

    if data['rcode'] == 'SERVFAIL':
        print("ERROR: Resolver encountered a server failure when querying a Name Server.")
        return
    elif data['rcode'] == 'NXDOMAIN':
        print(f"NAME ERROR: Server couldn't find record associated with {name}")
        return
    elif data['rcode'] == 'FORMERR':
        print("FORM ERROR: Server encountered a format issue with your query.")
        return

    enabledFlags = data['enabledFlags']

    qCount = data['qcount']

    ansCount = data['anscount']

    nsCount = data['nscount']

    arCount = data['arcount']
    print("Got Answer:")
    print(f"->>HEADER<<- opcode: {opCode}, status: {rCode}, id: {queryId}")

    print(f"flags: {enabledFlags}; QUERY: {qCount}, ANSWER: {ansCount}, AUTHORITY: {nsCount}, ADDITIONAL: {arCount}")

    print("QUESTION SECTION:")
    for count in range(0, qCount):
        qClassData = data['qClasses'][count]

        qType = data['qTypes'][count]
        print(f"{name}.\t\t{invertedClasses[qClassData]}\t{invertedTypes[qType]}")

    print("\nANSWER SECTION:")
    for count in range(0, ansCount):
        ansExtras = data['answersExtras'][count]
        ansType = ansExtras["ansType"]
        ansClass = ansExtras["ansClass"]
        ansTTL = ansExtras["ansTTL"]
        ansRdlength = ansExtras["ansRdlength"]

        answer = data['answers'][count]
        if ansType == qType:
            print(f"{name}\t{ansTTL}\t{invertedClasses[ansClass]}\t{invertedTypes[ansType]}\t{answer}")
    print("\n")
    print("AUTHORITY SECTION:")
    for count in range(0, nsCount):
        authExtras = data['nsExtras'][count]
        authType = authExtras["ansType"]
        authClass = authExtras["ansClass"]
        authTTL = authExtras["ansTTL"]
        authRdlength = authExtras["ansRdlength"]

        answer = data['ns'][count]
        print(f"{name}\t{authTTL}\t{invertedClasses[authClass]}\t{invertedTypes[authType]}\t{answer}")
if len(sys.argv) < 5:
    print("Error: invalid arguments\nUsage: python3 Client.py [resolver_ip] [resolver_port] [name] [type] [timeout=5]", file=sys.stderr)
    sys.exit()

resolverIP = sys.argv[1]

resolverPort = sys.argv[2]

name = sys.argv[3]

queryTypeArg = sys.argv[4].upper()

if len(sys.argv) < 6:
    timeout = 10
elif len(sys.argv) == 6:
    timeout = sys.argv[5]

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

client.settimeout(float(timeout))

timeStart = time.time()
# UDP is connectionless so no connecting to server like with TCP.
client.sendto(createQuery(queryTypeArg), (resolverIP, int(resolverPort)))
try:
    modifiedMessage, serverAddress = client.recvfrom(2048)
    timeEnd = time.time()
except socket.timeout:
    timeEnd = time.time()
    print("ERROR TIMEOUT: Client did not recieve response within timeout period.")
    print(f"\nQuery time: {round(timeEnd - timeStart, 4)} sec")
    exit()

if len(modifiedMessage) < 12:
    print("ERROR TIMEOUT: All DNS Servers contacted by resolver timed out.")
    print(f"\nQuery time: {round(timeEnd - timeStart, 4)} sec")
    exit()

printResponse(modifiedMessage)

print(f"\nQuery time: {round(timeEnd - timeStart, 4)} sec")

client.close()



























