import re

def srcIP():
    ipAddress = input("What is the source IP Address: ")
    validIpAddress = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ipAddress)
    while validIpAddress != None:
        ipAddress = input("Please enter a valid IP Address: ")
        validIpAddress = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ipAddress)
    return (ipAddress)

def dstIP():
    validIpAddress = None
    ipAddress = input("What is the destination IP Address: ")
    validIpAddress = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ipAddress)
    while validIpAddress != None:
        ipAddress = input("Please enter a valid IP Address: ")
        validIpAddress = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ipAddress)
    return (ipAddress)

def srcMAC():
    validMacAddress = None
    macAddress = input("What is the source MAC Address: ")
    validMacAddress = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', macAddress, re.I).group()
    while validMacAddress != None:
        macAddress = input("Please enter a valid MAC address: ")
    return (macAddress)

def dstMAC():
    validMacAddress = None
    macAddress = input("What is the source MAC Address: ")
    validMacAddress = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', macAddress, re.I).group()
    while validMacAddress != None:
        macAddress = input("Please enter a valid MAC address: ")
        validMacAddress = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', macAddress, re.I).group()
    return (macAddress)

def UDPCreate():
    print("UDP File format")

def TCPCreate():
    print("TCP File format")

def ICMPCreate():
    print("ICMP file format")

def HTTPCreate():
    print("HTTP File format")

def HTTPSCreate():
    print("HTTPS file format")

def ARPCreate():
    print("ARP file format")

def DHCPCreate():
    print("DHCP file format")

#Function used to define the User's desired protocol
def NetworkPacketCreate():
    while True:
        protocol = input("What protocol PCAP file do you want to create?\nUDP\tTCP\tICMP\tHTTP\tHTTPS\tARP\tDHCP\n")
        if protocol == "UDP" or protocol == "udp":
            UDPCreate()
            break
        elif protocol == "TCP" or protocol == "tcp":
            TCPCreate()
            break
        elif protocol == "ICMP" or protocol == "icmp":
            ICMPCreate()
            break
        elif protocol == "HTTP" or protocol == "http":
            HTTPCreate()
            break
        elif protocol == "HTTPS" or protocol == "https":
            HTTPSCreate()
            break
        elif protocol == "ARP" or protocol == "arp":
            ARPCreate()
            break
        elif protocol == "DHCP" or protocol == "dhcp":
            DHCPCreate()
            break
        else:
            print("Invalid protocol, please use one of the protocols defined")

NetworkPacketCreate()