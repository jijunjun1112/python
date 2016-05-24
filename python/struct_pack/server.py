#!/usr/bin/env python
import struct
from socket import *
from time import ctime

HOST = ''
PORT = 8801
ADDR = (HOST, PORT)

servSock = socket(AF_INET, SOCK_STREAM)
servSock.bind(ADDR)
servSock.listen(5)

while True: 
    print "waiting for connection..."
    cliSock, addr = servSock.accept()
    print "...connected from:", addr

    while True:
        data = cliSock.recv(1024)
        print "data:"+data
        if not data:
            break

        msg_len, cmd_id = struct.unpack_from('!2i', data, 0)
        print msg_len, cmd_id
        if(cmd_id == 304):
            roomno, sequence, type, name_ch, code, count, price, total = struct.unpack_from('!16sQ50s50s16sQ6s6s', data, 8)
            print "order:", roomno, sequence, type.decode('gb2312'), name_ch.decode('gb2312'), code, count, price, total

        bytes = struct.pack('!2i', 32769, 8)
        cliSock.send(bytes)

    cliSock.close() 

servSock.close() 