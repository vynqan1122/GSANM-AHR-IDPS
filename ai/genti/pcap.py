"""Controlled HTTP packets for the runtime native validation gate."""
import socket
import struct

def checksum(data):
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack(f'!{len(data)//2}H',data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535

def tcp_case(port, method, uri, host='dvwa.local'):
    request = f'{method} {uri} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode()
    response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK'
    packets=[]
    for rev, seq, ack, flags, data in [(False,1000,0,2,b''),(True,5000,1001,18,b''),
        (False,1001,5001,16,b''),(False,1001,5001,24,request),
        (True,5001,1001+len(request),24,response),(False,1001+len(request),5001+len(response),16,b'')]:
        src,dst=('10.88.0.20','10.88.0.10') if rev else ('10.88.0.10','10.88.0.20')
        tcp=struct.pack('!HHIIBBHHH',80 if rev else port,port if rev else 80,seq,ack,80,flags,65535,0,0)+data
        pseudo=socket.inet_aton(src)+socket.inet_aton(dst)+struct.pack('!BBH',0,6,len(tcp))
        tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
        ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),0,0,64,6,0,socket.inet_aton(src),socket.inet_aton(dst))
        ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
        assert checksum(ip)==0 and checksum(pseudo+tcp)==0
        packets.append(b'\x00\x11\x22\x33\x44\x55'*2+b'\x08\x00'+ip+tcp)
    return packets
