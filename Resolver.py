import socket
import sys
import struct
from helpers import parseResponse
import copy

def checkIfAnswer(response):
    if len(response) < 12:
        return False
    byteHeader = response[0:12] # First 12 bytes are the header as specified by RFC 1035.

    unpackedHeader = struct.unpack('!HHHHHH', byteHeader) # Get header

    qCount, ansCount, nsCount, arCount = unpackedHeader[2:] # Pos 0 is ID, Pos 1 is Flags, Pos 2-5 is counts

    if ansCount > 0:
        return True
    # elif ansCount == 0 and nsCount > 0 and arCount == 0:
    #     return True # If answer in ns section from NS query, and no additional section
    #     # There is no next server to go to and the answer is in NS section.
    return False

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Error: invalid arguments\nUsage: python3 Resolver.py [resolver_port] [timeout=5]", file=sys.stderr)
    sys.exit()
serverPort = int(sys.argv[1])

# Note: Confirmed that client and resolver timeouts dont have to match:
# https://edstem.org/au/courses/11968/discussion/1467216
# Implementation based on this assumption as not specified otherwise in specification:
if len(sys.argv) > 2:
    timeout = sys.argv[2]
else:
    timeout = 5

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

dnsSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

serverSocket.bind(('localhost', serverPort))

clientAddress = None

clientQuery = None

dnsSocket.settimeout(float(timeout))

# Reference: File reading format obtained from:
# https://stackoverflow.com/questions/15599639/what-is-the-perfect-counterpart-in-python-for-while-not-eof
# By dawg

rootServers = []

currServer = None

timeOut = False

prevData = None

with open("named.root", 'r') as f:
    while True:
        line = f.readline()
        if len(line) > 0 and line[0] != ';' and line[0] != '.':
            data = line.split(' ')
            data = [item for item in data if item != '' and item != ' ']
            if data[2] != 'AAAA':
                rootServers.append(data[3].replace('\n', ''))
        if not line:
            break
while True:
    timeOut = False
    if clientQuery == None:
        message, address = serverSocket.recvfrom(2048) # Recieve request from client
        clientQuery = message
        currServer =  rootServers[0] # Get first root server IP
        clientAddress = address
        dnsSocket.sendto(clientQuery, (currServer, 53)) # Else start sending to next server.

    else:
        try:
            message, address = dnsSocket.recvfrom(2048) # Recieve request from client
            isAnswer = checkIfAnswer(message)
        except socket.timeout:
            isAnswer = False
            timeOut = True
        # Check if an answer was recieved from server.
        if isAnswer:

            data = parseResponse(message, False)
            serverSocket.sendto(message, clientAddress) # Send it back to client for parsing.
            clientAddress = None
            clientQuery = None
        else:
            if timeOut:
                if currServer == rootServers[-1]:
                    message = "timeout".encode()
                    serverSocket.sendto(message, clientAddress) # Send it back to client for parsing as all roots exhausted.
                    clientAddress = None
                    clientQuery = None
                elif currServer in rootServers and currServer != rootServers[-1]:
                    currServer = rootServers[rootServers.index(currServer) + 1]
                    dnsSocket.sendto(clientQuery, (currServer, 53)) # Else start sending to next server.
                elif len(prevData['additionals']) > 0:
                    currServer = prevData['additionals'][0]
                    dnsSocket.sendto(clientQuery, (currServer, 53)) # Else start sending to next server.
                    prevData['additionals'].pop(0) # Remove exhausted ip
                else:
                    message = "timeout".encode()
                    serverSocket.sendto(message, clientAddress) # Send it back to client for parsing as all roots exhausted.
                    clientAddress = None
                    clientQuery = None
            else:
                data = parseResponse(message, False)
                # If some issue occurs with the server, exhaust all ips
                if data['rcode'] == 'SERVFAIL' or data['rcode'] == 'REFUSED' or data['additionals'] == []:
                    if currServer == rootServers[-1]:
                        serverSocket.sendto(message, clientAddress) # Send it back to client for parsing as all roots exhausted.
                        clientAddress = None
                        clientQuery = None
                    elif currServer in rootServers and currServer != rootServers[-1]:
                        currServer = rootServers[rootServers.index(currServer) + 1]
                        dnsSocket.sendto(clientQuery, (currServer, 53)) # Else start sending to next server.
                    elif len(prevData['additionals']) > 0:
                        currServer = prevData['additionals'][0]
                        dnsSocket.sendto(clientQuery, (currServer, 53)) # Else start sending to next server.
                        prevData['additionals'].pop(0) # Remove exhausted ip
                    else:
                        serverSocket.sendto(message, clientAddress) # Send it back to client for parsing as all roots exhausted.
                        clientAddress = None
                        clientQuery = None
                elif data['rcode'] == 'NXDOMAIN' or data['rcode'] == 'FORMERR':
                    serverSocket.sendto(message, clientAddress) # Send it back to client for parsing.
                    clientAddress = None
                    clientQuery = None # End query resolving processs.
                else:
                    currServer = data['additionals'][0]
                    dnsSocket.sendto(clientQuery, (currServer, 53)) # Else start sending to next server.
                    data['additionals'].pop(0) # Remove exhausted ip
                    if data['additionals'] != []:
                        prevData = copy.deepcopy(data)
                     # Only save data from last iterative query once a valid response was given.







