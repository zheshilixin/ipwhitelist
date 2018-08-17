# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
from elasticsearch import Elasticsearch
import IPy
from IPy import IP
import white_test
import time,datetime

import ConfigParser
cp = ConfigParser.ConfigParser()

es2 = Elasticsearch(['192.168.10.65'], port=9200)

class ESclient(object):
    def __init__(self, server='192.168.0.122', port='9222'):
        self.__es_client = Elasticsearch([{'host': server, 'port': port}])

    es = Elasticsearch(['192.168.0.122'], port=9222)
    f = open('whitelist.txt')

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

#get four dateset from four match methods , insert separately
# msg is original data

'''
#def insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch,segmentmatch,subnetlpm,subnetfull,msg):
def insert_result(index, aggs_name, timestamp, fullmatch, segmentmatch, subnetlpm, subnetfull,
                      msg):
    es_insert = ESclient(server='192.168.10.65', port=9200)
    #mylog=blacklist_tools.getlog()
    #white list filter ips
    if len(fullmatch) > 0:
        for i in range(len(fullmatch)):
            doc = {}
            doc['level'] = msg[fullmatch[i]]['level']
            doc['type']='fakeDIP'
            doc['desc_type']='[fake_DIP] Request of suspect IP detection.'
            doc['desc_subtype'] = msg[fullmatch[i]]['desc_subtype']
            doc['subtype']=msg[fullmatch[i]]['subtype']
            doc['match_type'] = "full_match"
            doc[aggs_name] = fullmatch[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'full_match_insert'
        mylog.info('full_match_insert')

    if len(segmentmatch) > 0:
        for i in range(len(segmentmatch)):
            # segment insert
            ip_es=segmentmatch[i].keys()[0]
            # print ip_es
            ipseg=segmentmatch[i][ip_es]
            # print ipseg
            doc = {}
            doc['level'] = msg[ipseg]['level']
            doc['type'] = 'MAL_IP'
            doc['desc_type'] = '[MAL_IP] Request of suspect IP detection.'
            doc['desc_subtype'] = msg[ipseg]['desc_subtype']
            doc['subtype'] = msg[ipseg]['subtype']
            doc['match_type'] = "segment_match"
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'segment_insert'
        mylog.info('segment_insert')

    if len(subnetlpm) > 0:
        for i in range(len(subnetlpm)):
            # segment insert
            ip_es=subnetlpm[i].keys()[0]
            # print ip_es
            ipseg=subnetlpm[i][ip_es]
            # print ipseg
            key1=msg.keys()[0]
            doc = {}
            doc['level'] = msg[key1]['level']
            doc['type'] = 'MAL_IP'
            doc['desc_type'] = '[MAL_IP] Request of suspect IP detection.'
            tmptype=msg[key1]['desc_subtype'].split(';')
            doc['desc_subtype'] = tmptype[0].split(':')[0]+';'+tmptype[1]
            doc['subtype'] = msg[key1]['subtype']
            doc['match_type'] = 'subnet_lpm_match'
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'subnet_lpm_insert'
        mylog.info('subnet_lpm_insert')

    if len(subnetfull) > 0:
        for i in range(len(subnetfull)):
            # segment insert
            ip_es=subnetfull[i].keys()[0]
            # print ip_es
            ipseg=subnetfull[i][ip_es]
            # print ipseg
            doc = {}
            doc['level'] = msg[ipseg]['level']
            doc['type'] = 'MAL_IP'
            doc['desc_type'] = '[MAL_IP] Request of suspect IP detection.'
            doc['desc_subtype'] = msg[ipseg]['desc_subtype']
            doc['subtype'] = msg[ipseg]['subtype']
            doc['match_type'] = 'subnet_fullmatch'
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'subnet_full_insert'
        mylog.info('subnet_full_insert')
'''
def compare_data(esdata,whitelistdata):
    res_es = []
    for key in esdata:
        res_es.append(IP(key))
    fakedip = (set(res_es))-(set(whitelistdata))
    return fakedip

def insert_es_alert(doc):
    result = es2.index(
        index='alert-{}'.format(datetime.datetime.now().strftime('%Y-%m-%d')),
        doc_type='netflow_v9',
        body=doc
    )
    time1 = format(datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
    print (time1)
    print("insert done")
    return result

def getCheckDeltatime():
    #check frequency
    timekey1=cp.options("delta_time_check")
    times=cp.getint("delta_time_check",timekey1[0])
    deltatime=datetime.timedelta(minutes=times)
    timekey2=cp.options("frequency")
    starttime=cp.get("frequency",timekey2[0])
    return deltatime,starttime

def insert_sample(idel_test,index,gte,lte,faked):
    # 此处是用来调用配置的时间，暂时用不到
    # discard = getCheckDeltatime()
    # startTime = datetime.datetime.strptime(discard, '%Y-%m-%d %H:%M:%S')
    # if (time.daylight == 0):  # 1:dst;
    #     time_zone = "%+03d:%02d" % (-(time.timezone / 3600), time.timezone % 3600 / 3600.0 * 60)
    # else:
    #     time_zone = "%+03d:%02d" % (-(time.altzone / 3600), time.altzone % 3600 / 3600.0 * 60)
    # timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S.%f') + time_zone

    time_zone_CST = "%+03d:%02d" % (-(time.timezone / 3600), time.timezone % 3600 / 3600.0 * 60)
    timestamp = (datetime.datetime.now()).strftime('%Y-%m-%dT%H:%M:%S.%f') + time_zone_CST
    doc = {}
    doc['type'] = 'sip'
    doc['subnet_segment_count'] = len(faked)
    doc['subnet_setment'] = faked
    doc['desc_type'] = '[sip] sip not in whitelist'
    doc['@timestamp'] = timestamp
    doc['index'] = 'tcp-*'
    result = insert_es_alert(doc)
    return result

def ipy2unit(ipyip):
    list = []
    for key in ipyip:
        list.append(str(key).decode('utf-8'))
    return list

def main(interval):
    start = time.clock()
    now = time.time()
    sec_now = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(now))
    time_list = []
    sec_now_split = sec_now.split('-')
    for key in sec_now_split:
        time_list.append(key)
    index_test = 'tcp-' + time_list[0] + '-' + time_list[1] + '-' + time_list[2]
    gte = int(round(now - 60*interval) * 1000)
    lte = int(round(now) * 1000)
    idel_test = ESclient()
    res = list(idel_test.get_es_ip(index=index_test, gte=gte, lte=lte, aggs_name='sip'))
    print res
    print (type(res))
    print (type(res[0]))
    # res = list(ESclient.get_es_ip(index='tcp-2018-07-30',gte=1532880036000,lte=1532962836000,aggs_name='sip'))
    # 插入alert暂时有问题，目前注释掉 貌似是输入es因为中文报错
    #print (alert)
    running0 = time.clock()
    wl = white_test.getwl_cidr()
    runing1 = time.clock()
    faked = compare_data(res, wl)

    print ('ipy2unit:   ')
    faked_uni = ipy2unit(faked)
    #faked_uni = unicode(str(list(faked)))
    print(faked_uni)
    print (type(faked_uni))
    print (type(faked_uni[0]))
    insert_sample(idel_test, index_test, gte, lte, faked_uni)
    end = time.clock()
    print('get es data time: %s Seconds' % (running0 - start))
    print('get whitelist data time: %s Seconds' % (runing1 - running0))
    print('compare time: %s Seconds' % (end - runing1))
    print('All time:%s Seconds' % (end - start))

if __name__ == '__main__':
    interval = input("你想获得多久的数据(从当前时间往前按分钟计算）： ")
    main(interval)