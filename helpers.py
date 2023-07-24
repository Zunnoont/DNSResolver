import sys
import socket
import struct

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

dnsData = {}

invertedTypes = {v: k for k, v in types.items()}

invertedClasses = {v: k for k, v in qclass.items()}

dnsResponse = None


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

def getName(response, entireQuery):
    nameSize = 0

    # The compression scheme allows a domain name in a message to be
    # represented as either:

    #      - a sequence of labels ending in a zero octet - Case 1

    #    - a pointer - Case 2

    #    - a sequence of labels ending with a pointer - Case 3
    name = ""
    try:
        while True:
            currByte = response[nameSize]
            nameSize += 1
            if(currByte == 0):
                break # Null terminator reached (Case 1)
            elif currByte & 0xC0 == 0xC0:
                nameSize += 1 # Pointer is 2 octet.
                pointer = ((currByte & 0x3F) << 8)  + response[nameSize - 1]

                remainderName = entireQuery[pointer:]
                name += getName(remainderName, entireQuery) # Get name pointer is pointing to
                break # Found pointer at end of name section (Case 2 or 3)
            if response[nameSize] == 0:
                break

            name += response[nameSize : nameSize + currByte].decode('utf-8') + "."

            nameSize += currByte # If not, must be sequence label length
    except:
        return name


    return name
def parseAnswer(response, sectionName):

    index = parseNameSection(response) # Skip over name section

    ansType, ansClass, ansTTL, ansRdlength = struct.unpack('!HHLH', response[index:12])

    rData = struct.unpack('!' + 'B'*ansRdlength, response[12: 12 + ansRdlength])

    index = 12 + ansRdlength


    if ansType in invertedTypes:
        answer = list(rData)
        answer = [str(item) for item in answer]
        answer = '.'.join(answer)
        dnsData[sectionName].append(answer)
        if getName(response[12: 12 + ansRdlength], dnsResponse) != "" and sectionName == 'ns':
            dnsData[sectionName].append(getName(response[12: 12 + ansRdlength], dnsResponse))

    return index

def getAnswer(response):
    index = parseNameSection(response) # Skip over name section

    ansType, ansClass, ansTTL, ansRdlength = struct.unpack('!HHLH', response[index:12])

    rData = struct.unpack('!' + 'B'*ansRdlength, response[12: 12 + ansRdlength])

    index = 12 + ansRdlength
    answer = list(rData)
    answer = [str(item) for item in answer]
    answer = '.'.join(answer)

    return answer
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

    global dnsResponse; dnsResponse = response

    byteHeader = response[0:12] # First 12 bytes are the header as specified by RFC 1035.

    unpackedHeader = struct.unpack('!HHHHHH', byteHeader) # Get header

    queryId = unpackedHeader[0]

    dnsData['id'] = queryId

    flags = separateFlags(unpackedHeader[1])

    dnsData['flags'] = flags

    opCode = opcodeTypes[flags["opcode"]]

    rCode = rcodeTypes[flags["rcode"]]

    flags.pop("opcode")
    flags.pop("rcode")

    usedFlags =  {k:v for (k,v) in flags.items() if v == 1}

    enabledFlags = ' '.join(usedFlags.keys())

    dnsData['enabledFlags'] = enabledFlags

    qCount, ansCount, nsCount, arCount = unpackedHeader[2:] # Pos 0 is ID, Pos 1 is Flags, Pos 2-5 is counts
    answerIndex = 0

    dnsData['qcount'] = qCount
    dnsData['anscount'] = ansCount
    dnsData['nscount'] = nsCount
    dnsData['arcount'] = arCount

    for count in range(0, qCount):
        answerIndex = parseQuestion(response[(12 + answerIndex):])

        qType = struct.unpack("!H", response[12 + answerIndex: 14 + answerIndex])[0] # answerIndex + 12 starts at qtype,

        qClassData = struct.unpack("!H", response[14 + answerIndex: 16 + answerIndex])[0] ## answerIndex + 14 starts at qclass

        answerIndex += 4 # Got data from 4 bytes containing qtype and qclass.

    answerIndex += 12

    dnsData['answers'] = []
    dnsData['ns'] = []
    dnsData['additionals'] = []
    for count in range(0, ansCount):
        # Have to update answer index here
        answerIndex += parseAnswer(response[answerIndex:], 'answers')
    for count in range(0, nsCount):
        answerIndex += parseAnswer(response[answerIndex:], 'ns')
    for count in range(0, arCount):
        answerIndex += parseAnswer(response[answerIndex:], 'additionals')
    return dnsData