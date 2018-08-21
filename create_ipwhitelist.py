# -*- coding: utf-8 -*-
import IPy
from IPy import IP
import time,datetime
import re
from elasticsearch import Elasticsearch
import socket,struct
import ConfigParser

cp = ConfigParser.ConfigParser()
f = open('whitelist.txt')
whitelist = list(set(re.split(r"[,\n]",f.read())))
whitelist.remove('')
ip_cidr  = []
ip_range = []
ip_list = []
es2 = Elasticsearch(['192.168.10.65'], port=9200)
for ip_keys in whitelist:
    if re.match(r"^((?:(2[0-4]\d)|(25[0-5])|([01]?\d\d?))\.){3}(?:(2[0-4]\d)|(255[0-5])|([01]?\d\d?))$",ip_keys):
        ip_list.append(ip_keys)
    elif re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$", ip_keys):
        ip_cidr.append(ip_keys)
    elif re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\-(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_keys):
        ip_range.append(ip_keys)
    else:
        print ("you have error ip in whitelist")

class ESclient(object):
    def __init__(self, server='192.168.0.122', port='9222'):
        self.__es_client = Elasticsearch([{'host': server, 'port': port}])
    es = Elasticsearch(['192.168.0.122:9222'], port=9222)
    def get_es_ip(self,index,gte,lte,aggs_name):
        search_option3 = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": "sip:[192.168.0.0 TO 192.168.255.255]",
                                "analyze_wildcard": True
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "epoch_millis"
                                }
                            }
                        }
                    ],
                    "must_not": []
                }
            },
            "_source": {
                "excludes": []
            },
            "aggs": {
                "2": {
                    "terms": {
                        "field": aggs_name,
                        "size": 100,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            }
        }
        search_result = self.es.search(index=index,body=search_option3)
        clean_search_result = search_result['aggregations']['2']['buckets']
        ip = []
        for temp in clean_search_result:
            ip.append(temp['key'])
        return ip

#若ip_list非常多，可用字典树

def compare_ip_cidr(sip,ip_cidr):
    for cidr_key in ip_cidr:
        if ((sip in IP(cidr_key)) == False):
            continue
        else:
            return sip

def compare_ip_range(sip,ip_range):
    sip_bin = socket.ntohl(struct.unpack("I", socket.inet_aton(str(sip)))[0])
    for range_key in ip_range:
        ip_seg = range_key.split('-')
        A = ip_seg[0]
        B = ip_seg[1]
        num_ip_A = socket.ntohl(struct.unpack("I",socket.inet_aton(str(A)))[0])
        num_ip_B = socket.ntohl(struct.unpack("I", socket.inet_aton(str(B)))[0])
        if (sip_bin >= num_ip_A and sip_bin <= num_ip_B):
            return sip
        else:
            continue

def compare_data(res):
    get_ip_list = list((set(res) - set(ip_list)))
    new_ip_range = []
    #将ip段格式的ip转换为cidr格式的ip(若可以）
    for range_key in ip_range:
        try:
            ip_cidr.append(IP(range_key))
        except:
            new_ip_range.append(range_key)

    fake_list = []
    for sip in get_ip_list:
        fake_sip = compare_ip_cidr(sip,ip_cidr)
        if(fake_sip):
            fake_list.append(fake_sip)
        else:
            continue
    get_ip_cidr =  list(set(get_ip_list) - set(fake_list))

    get_ip_range = []
    for sip in get_ip_cidr:
        get_ip_range.append(compare_ip_range(sip,new_ip_range))
    res_fake_ip =  list(set(get_ip_cidr) - set(get_ip_range))
    return res_fake_ip

def getCheckDeltatime():
    #check frequency
    timekey1=cp.options("delta_time_check")
    times=cp.getint("delta_time_check",timekey1[0])
    deltatime=datetime.timedelta(minutes=times)
    timekey2=cp.options("frequency")
    starttime=cp.get("frequency",timekey2[0])
    return deltatime,starttime

def insert_es_alert(doc):
    result = es2.index(
        index='alert-{}'.format(datetime.datetime.now().strftime('%Y-%m-%d')),
        doc_type='netflow_v9',
        body=doc
    )
    time1 = format(datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
    return result

#def insert_sample(idel_test,index,gte,lte,faked):
    # 此处是用来调用配置的时间，暂时用不到
    # discard = getCheckDeltatime()
    # startTime = datetime.datetime.strptime(discard, '%Y-%m-%d %H:%M:%S')
    # if (time.daylight == 0):  # 1:dst;
    #     time_zone = "%+03d:%02d" % (-(time.timezone / 3600), time.timezone % 3600 / 3600.0 * 60)
    # else:
    #     time_zone = "%+03d:%02d" % (-(time.altzone / 3600), time.altzone % 3600 / 3600.0 * 60)
    # timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S.%f') + time_zone
def insert_sample(faked):
    time_zone_CST = "%+03d:%02d" % (-(time.timezone / 3600), time.timezone % 3600 / 3600.0 * 60)
    timestamp = (datetime.datetime.now()).strftime('%Y-%m-%dT%H:%M:%S.%f') + time_zone_CST
    doc = {}
    doc['sip']  = faked
    doc['type'] = 'suspect_ip'
    doc['desc_type'] = '[suspect_ip] Request of suspect IP detection.'
    doc['level'] = 'info'
    doc['@timestamp'] = timestamp
    doc['index'] = 'tcp-*'
    result = insert_es_alert(doc)
    print ("insert done")
    print timestamp
    return result

def main(interval):
    start = time.clock()
    now = time.time()
    sec_now = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(now))
    time_list = []
    sec_now_split = sec_now.split('-')
    for key in sec_now_split:
        time_list.append(key)
    index_test = 'tcp-' + time_list[0] + '-' + time_list[1] + '-' + time_list[2]
    gte = int(round(now - 60 * interval) * 1000)
    lte = int(round(now) * 1000)
    idel_test = ESclient()
    res = list(idel_test.get_es_ip(index=index_test, gte=gte, lte=lte, aggs_name='sip'))
    res_fake = compare_data(res)
    print res_fake
    insert_sample(res_fake)
    end = time.clock()
    print('Running time: %s Seconds' % (end - start))

if __name__ == '__main__':
    interval = input("你想获得多久的数据(从当前时间往前按分钟计算）： ")
    main(interval)