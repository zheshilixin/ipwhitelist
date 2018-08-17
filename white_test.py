from IPy import IP
import IPy
# if '192.168.0.1' in IP('192.168.0.0/30'):
#     print "My IP is in the whitelisy! yay!"

# IP = '192.168.10.65'
# def addr2dec(addr):
#     items = [int(x) for x in addr.split(".")]
#     return bin(sum([items[i] << [24,16,8,0][i] for i in range(4)]))
# dec = addr2dec(IP)
#f2 = open("wltest.txt",'w')
# f.write(dec)
def getwl_cidr():
    f = open('whitelist.txt')
    whitelist = []
    ws = f.read()
    whitelist = ws.split(',')
    whitelist2 = []
    for ipl in whitelist:
        ip = IPy.IP(ipl)
        for x in ip:
            whitelist2.append(x)
    return whitelist2
    #return set(whitelist2)

