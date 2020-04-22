
import sys
import binascii

port = 0000

#Custom Foo Protocol Packet
message =  ('01 01 00 08'   #Foo Base Header
            '01 02 00 00'   #Foo Message (31 Bytes)
            '00 00 12 30'   
            '00 00 12 31'
            '00 00 12 32' 
            '00 00 12 33' 
            '00 00 12 34' 
            'D7 CD EF'      
            '00 00 12 35')     


#############################################################################################################

#Global header for pcap 2.4
pcap_global_header =   ('D4 C3 B2 A1'   
                        '02 00'         #File format major revision (i.e. pcap <2>.4)  
                        '04 00'         #File format minor revision (i.e. pcap 2.<4>)   
                        '00 00 00 00'     
                        '00 00 00 00'     
                        'FF FF 00 00'     
                        '01 00 00 00')

#pcap packet header that must preface every packet
pcap_packet_header =   ('AA 77 9F 47'     
                        '90 A2 04 00'     
                        'XX XX XX XX'   #Frame Size (little endian) 
                        'YY YY YY YY')  #Frame Size (little endian)

eth_header =   ('00 00 00 00 00 00'     #Source Mac    
                '00 00 00 00 00 00'     #Dest Mac  
                '08 00')                #Protocol (0x0800 = IP)

ip_header =    ('45'                    #IP version and header length (multiples of 4 bytes)   
                '00'                      
                'XX XX'                 #Length - will be calculated and replaced later
                '00 00'                   
                '40 00 40'                
                '11'                    #Protocol (0x11 = UDP)          
                'YY YY'                 #Checksum - will be calculated and replaced later      
                '7F 00 00 01'           #Source IP (Default: 127.0.0.1)         
                '7F 00 00 01')          #Dest IP (Default: 127.0.0.1) 

protocol_header=('80 01'                   
                'XX XX'                 #Port - will be replaced later                   
                'YY YY'                 #Length - will be calculated and replaced later        
                '00 00')
                
def getByteLength(str1):
    return len(''.join(str1.split())) / 2

def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()  
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'wb')
    bitout.write(bytes)

def generatePCAP(message,port,pcapfile): 

    udp = protocol_header.replace('XX XX',"%04x"%port)
    udp_len = getByteLength(message) + getByteLength(protocol_header)
    udp = udp.replace('YY YY',"%04x"%udp_len)

    ip_len = udp_len + getByteLength(ip_header)
    ip = ip_header.replace('XX XX',"%04x"%ip_len)
    checksum = ip_checksum(ip.replace('YY YY','00 00'))
    ip = ip.replace('YY YY',"%04x"%checksum)
    
    pcap_len = ip_len + getByteLength(eth_header)
    hex_str = "%08x"%pcap_len
    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
    pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
    pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)

    bytestring = pcap_global_header + pcaph + eth_header + ip + udp + message
    writeByteStringToFile(bytestring, pcapfile)

#Splits the string into a list of tokens every n characters
def splitN(str1,n):
    return [str1[start:start+n] for start in range(0, len(str1), n)]

#Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):

    #split into bytes    
    words = splitN(''.join(iph.split()),4)

    csum = 0
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum


"""------------------------------------------"""
""" End of functions, execution starts here: """
"""------------------------------------------"""

def UDPCreate():
    port = int(input("What is the port of the packet?: "))

def TCPCreate():
    port = int(input("What is the port of the packet?: "))

def ICMPCreate():
    port = int(input("What is the port of the packet?: "))

def HTTPCreate():
    port = int(input("What is the port of the packet?: "))

def HTTPSCreate():
    port = int(input("What is the port of the packet?: "))

def ARPCreate():
    port = int(input("What is the port of the packet?: "))

def DHCPCreate():
    port = int(input("What is the port of the packet?: "))

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


if len(sys.argv) < 2:
        print ('usage: pcapgen.py output_file')
        exit(0)

generatePCAP(message,port,sys.argv[1])  