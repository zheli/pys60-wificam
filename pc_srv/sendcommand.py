import sys
import socket
import os
import time
import struct
import re
import logging
logging.getLogger().setLevel(logging.DEBUG)

ip = '192.168.0.35'
port = 54321
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((ip, port))
except socket.error, (val,msg):
    logging.error('Error %d: %s' % (val, msg))
    sys.exit(-1)

logging.info('Sending command...')
cmd = 'take_photo\n'
s.sendall(cmd)
s.close()
