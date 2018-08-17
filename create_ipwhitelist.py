import IPy
from IPy import IP
import time,datetime
import re

start = time.clock()
f = open('whitelist.txt')
# f1 = open('cfg/ip_whitelist.txt', 'w')
# f2 = open('cfg/ip_ipboundy.txt','w')
# f3 = open('cfg/ip_cidr.txt','w')
whitelist = f.read().split(',')
ip_cidr  = []
ip_range = []
ip_list = []

for ip_keys in whitelist:
    #if re.match(r"(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d){1}", ip_keys):
    if re.match(r"^((?:(2[0-4]\d)|(25[0-5])|([01]?\d\d?))\.){3}(?:(2[0-4]\d)|(255[0-5])|([01]?\d\d?))$",ip_keys):
        ip_list.append(ip_keys)
    elif re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$", ip_keys):
        ip_cidr.append(ip_keys)
    elif re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\-(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_keys):
    #else:
        ip_range.append(ip_keys)
    else:
        print ("you have error ip")

print (ip_list)
print (ip_cidr)
print (ip_range)

sip = '10.12.13.14'
for cidr_list in ip_cidr:
    if sip in IP(cidr_list):
        print ("this %s in %s"%(sip,cidr_list))
end = time.clock()
print('Running time: %s Seconds'%(end-start))
'''
for ipl in whitelist:
    ip = IPy.IP(ipl)
    for x in ip:
        whitelist2.append(x)
f1.write(str(whitelist2))
'''
