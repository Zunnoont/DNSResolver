import subprocess
import time
import sys


def readDlist():
    domainNames = []
    with open("dlist4000.txt", 'r') as dList:
        for domain in dList:
            domainNames.append(domain.strip())
    return domainNames

def runClient():
    dnsResolverCommand = ['python3', 'Resolver.py', '5500', '5']
    dnsResolverProcess = subprocess.Popen(dnsResolverCommand) # Start resolver
    timeOutCounts = 0
    data = readDlist()
    for _ in range(2):
        for domain in data:
            command = ['python3', 'Client.py', '127.0.0.1', '5500', str(domain), 'A', '4']
            process = subprocess.run(command, capture_output=True, text=True)
            with open("performance/domains.txt", 'a+') as f:
                f.write(domain + "\n")
            with open("performance/resolutionTimes.txt", 'a+') as f2:
                f2.write(process.stdout.split(" ")[-2] + "\n")
            if float(process.stdout.split(" ")[-2]) > 4:
                timeOutCounts += 1
            if timeOutCounts > 3:
                dnsResolverProcess.terminate()
                dnsResolverProcess = subprocess.Popen(dnsResolverCommand) # restart resolver incase of overload on resolver or dns servers from too many queries.
            if domain == data[2499]:
                break

def runGoogleDNS():
    timeOutCounts = 0
    data = readDlist()
    for _ in range(2):
        for domain in data:
            command = ['python3', 'Client.py', '8.8.8.8', '53', str(domain), 'A', '4']
            process = subprocess.run(command, capture_output=True, text=True)
            with open("performance/googleDNSDomains.txt", 'a+') as f:
                f.write(domain + "\n")
            with open("performance/googleDNSResolutionTimes.txt", 'a+') as f2:
                f2.write(process.stdout.split(" ")[-2] + "\n")
            if float(process.stdout.split(" ")[-2]) > 4:
                timeOutCounts += 1
            if domain == data[2499]:
                break


def runCloudFareDNS():
    timeOutCounts = 0
    data = readDlist()
    for _ in range(2):
        for domain in data:
            command = ['python3', 'Client.py', '1.1.1.1', '53', str(domain), 'A', '4']
            process = subprocess.run(command, capture_output=True, text=True)
            with open("performance/cloudfareDNSDomains.txt", 'a+') as f:
                f.write(domain + "\n")
            with open("performance/cloudfareDNSResolutionTimes.txt", 'a+') as f2:
                f2.write(process.stdout.split(" ")[-2] + "\n")
            if float(process.stdout.split(" ")[-2]) > 4:
                timeOutCounts += 1
            if domain == data[2499]:
                break

def testResolver():
    dnsResolverCommand = ['python3', 'Resolver.py', '5600', '5']
    dnsResolverProcess = subprocess.Popen(dnsResolverCommand) # Start resolver
    timeOutCounts = 0
    data = readDlist()
    for _ in range(2):
        for domain in data:
            command = ['python3', 'Client.py', '127.0.0.1', '5600', str(domain), 'A', '4']
            process = subprocess.run(command, capture_output=True, text=True)
            print(process.stdout)
            if float(process.stdout.split(" ")[-2]) > 4:
                timeOutCounts += 1
            if timeOutCounts > 3:
                dnsResolverProcess.terminate()
                dnsResolverProcess = subprocess.Popen(dnsResolverCommand) # restart resolver incase of overload on resolver or dns servers from too many queries.
            if domain == data[2499]:
                break

if len(sys.argv) > 2:
    print("Error: Invalid Arguments. Usage: python3 performanceRunner.py [type=1]")
    print("Select 1 for Resolver.py, 2 for 8.8.8.8 Google DNS and 3 for 1.1.1.1 Cloudfare DNS")
    exit()

resolverType = 1
if len(sys.argv) == 2:
    resolverType = int(sys.argv[1])

if __name__ == '__main__':
    if resolverType == 1:
        runClient()
    elif resolverType == 2:
        runGoogleDNS()
    elif resolverType == 3:
        runCloudFareDNS()
    elif resolverType == 4:
        testResolver()


