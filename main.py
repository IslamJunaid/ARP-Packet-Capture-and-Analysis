import dpkt
import struct
import binascii
import socket

x = False
f = open('my_arp.pcap','rb')
pcap = dpkt.pcap.Reader(f)
for (ts,buffer) in pcap:
    header = buffer[14:42]
    data = struct.unpack("2s2s1s1s2s6s4s6s4s", header)
    if struct.unpack("!6s6s2s", buffer[0:14])[2] != b'\x08\x06':
        continue
    if (data[7]) == b'\x00\x00\x00\x00\x00\x00':
        continue
    if (data[5]) == b'\xaa\xbb\xcc\xdd\xee\xff':
        continue
    if data[4] == b'\x00\x01':
        print("ARP Request")
        hw_type = binascii.hexlify(data[0]).decode('utf-8')
        ptcl_type = binascii.hexlify(data[1]).decode('utf-8')
        hw_size = binascii.hexlify(data[2]).decode('utf-8')
        ptcl_size = binascii.hexlify(data[3]).decode('utf-8')
        Opcode = binascii.hexlify(data[4]).decode('utf-8')
        SMAC = binascii.hexlify(data[5]).decode('utf-8')
        SIP = socket.inet_ntoa(data[6])
        TMAC = binascii.hexlify(data[7]).decode('utf-8')
        TIP = socket.inet_ntoa(data[8])
        print("Hardware Type " + hw_type)
        print("Protocol Type " + ptcl_type)
        print("Hardware Size " + hw_size)
        print("Protocol size " + ptcl_size)
        print("Opcode " + Opcode)
        print("Sender MAC " + SMAC)
        print("Sender IP " + SIP)
        print("Target MAC " + TMAC)
        print("Target IP " + TIP)
        print("\n")

        x = True
    else:
        print("ARP RESPONSE")
        hw_type = binascii.hexlify(data[0]).decode('utf-8')
        ptcl_type = binascii.hexlify(data[1]).decode('utf-8')
        hw_size = binascii.hexlify(data[2]).decode('utf-8')
        ptcl_size = binascii.hexlify(data[3]).decode('utf-8')
        Opcode = binascii.hexlify(data[4]).decode('utf-8')
        SMAC = binascii.hexlify(data[5]).decode('utf-8')
        SIP = socket.inet_ntoa(data[6])
        TMAC = binascii.hexlify(data[7]).decode('utf-8')
        TIP = socket.inet_ntoa(data[8])

        print("Hardware Type " + hw_type)
        print("Protocol Type " + ptcl_type)
        print("Hardware Size " + hw_size)
        print("Protocol size " + ptcl_size)
        print("Opcode " + Opcode)
        print("Sender MAC " + SMAC)
        print("Sender IP " + SIP)
        print("Target MAC " + TMAC)
        print("Target IP " + TIP)
        print("\n")
        if x == True:
            break

