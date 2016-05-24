import socket, ssl, pprint,time
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.126.57', 8801))

n=0
t_send=0
t_recv=0
while n <1:
    n = n+1
    s.send(b'a'*10)
    data=s.recv(1024)
    msg_len, cmd_id = struct.unpack_from('!2i', data, 0)
    print msg_len,cmd_id
    msg_len, cmd_id = struct.unpack('!2i', data) # struct.unpack(fmt, string)

    print msg_len
    print cmd_id
 
s.close()
