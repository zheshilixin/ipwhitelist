import IPy
from IPy import IP
import time,datetime
import re

start = time.clock()
f = open('whitelist.txt')
f1 = open('cfg/ip_whitelist.txt', 'w')
f2 = open('cfg/ip_ipboundy.txt','w')
f3 = open('cfg/ip_cidr.txt','w')
ws = f.read()
whitelist = ws.split(',')
whitelist1 = []
whitelist2 = []
whitelist3 = []
for ip in whitelist:
    if ()

'''
for ipl in whitelist:
    ip = IPy.IP(ipl)
    for x in ip:
        whitelist2.append(x)
f1.write(str(whitelist2))
'''


end = time.clock()
print(end - start)