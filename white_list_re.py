import IPy
import re
import time
start = time.clock()
f = open('whitelist.txt')
whitelist = f.read().split(',')
whitelist2 = []
for ipl in whitelist:
    ip = IPy.IP(ipl)
    for x in ip:
        whitelist2.append(x)
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
end = time.clock()
print('Running time: %s Seconds'%(end-start))