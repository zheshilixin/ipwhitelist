# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
from elasticsearch import Elasticsearch
import IPy
from IPy import IP
import white_test
import time
import json
import datetime, sys
import os
# start = time.clock()
es = Elasticsearch(['192.168.0.122'], port=9222)
f = open('whitelist.txt')
# cidr = []
# ws = f.read()
# wl_cidr = ws.split(',')
# cidr = []
# for ipl in wl_cidr:
#     ip = IPy.IP(ipl)
#     for x in ip:
#         cidr.append(x)


def get_es_ip(index,gte,lte,aggs_name):
    search_option = {
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
                "must_not": [ ]
            }
        },
        "_source": {
            "excludes": [ ]
        },
        "aggs": {
            "2": {
                "terms": {
                    "field": "sip",
                    "size": 100,
                    "order": {
                        "_count": "desc"
                    }
                }
            }
        }
    }

    search_option2 = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "sip:[192.168.0.0 TO 192.168.255.255] AND unknown_conn:0",
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
                    "size": 50,
                    "order": {
                        "1": "desc"
                    },
                    "execution_hint": "map"
                },
                "aggs": {
                    "1": {
                        "cardinality": {
                            "field": aggs_name
                        }
                    }
                }
            }
        }
    }

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

    search_result = es.search(index=index,body=search_option3)
    clean_search_result = search_result['aggregations']['2']['buckets']
    ip = []
    for temp in clean_search_result:
        ip.append(temp['key'])
    return ip
    # ip_es_list = es.get_es_ip(index,gte,lte,aggs_name,time_zone)

def unicode2list(list):
    str_symptom = str(list).replace('u\'','\'')
    return str_symptom
def IP2list(list):
    str_sysptom = str(list).replace('IP(\'','\'')
if __name__ == '__main__':
    now = time.time()
    time_range = 300
    time_lte = int(round(now) * 1000)
    time_gte = int(round(now-time_range)*1000)
    res = list(get_es_ip('tcp-2018-07-30',1532880036000,1532962836000,'sip'))
    start = time.clock()
    resc = []
    # f5 = open("get_rawes_data.txt",'w')
    # f5.write(str(res))
    # f5.close()
    for resi in res:
        resc.append(IP(resi))
    # print (resc.__len__())
    wl = white_test.getwl_cidr()

    # f3 = open("get_es_data.txt",'w')
    # f4 = open("the_whitelist.txt",'w')
    # f3.write(str(resc))
    # f4.write(str(wl))
    # f3.close()
    # f4.close()
    # print (res_list)
    # for ip_list in cidr:
    #     for ip_key in res:
    #         if (ip_key in IP(ip_list)):
    #             print ip_key

    fakedip = []
    print (wl.__len__())
    for get_key in resc:
        if get_key in wl:
            continue
            # print ("you are secure: "+str(get_key))
        else:
            fakedip.append(get_key)

print fakedip
end = time.clock()
print('Running time: %s Seconds'%(end-start))