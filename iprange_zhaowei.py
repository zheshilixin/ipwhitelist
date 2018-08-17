#!/usr/bin/python
# -*- coding: utf-8 -*-
#zhaowei
from IPy import IP
from elasticsearch import Elasticsearch
import json
import datetime,sys,time
import os

'''
class ESclient(object):
	def __init__(self, server='192.168.10.103', port='9200'):
		self.__es_client = Elasticsearch([{'host': server, 'port': port}])
'''
es = Elasticsearch(
    ['192.168.10.65'],
    port=9200
)

def get_es_ip(index,gte,lte,aggs_name):
    search_option={
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

    result= es.search(index=index, body=search_option)

    search_result = result['aggregations']['2']['buckets']
   # return search_result
    ip_es = []
    for temp in search_result:
        ip_es.append(temp['key'])
    return ip_es

    #
    # iplist = []
    # count = 0
    # while count <= 255:
    #     a = '192.168.{0}.0-192.168.{0}.255'.format(count)
    #     iplist.append(a)
    #     count += 1
    #
    # subnet_segment = set()
    # for iplist_single in iplist:
    #     for ip_es_single in ip_es:
    #         if ip_es_single in IP(iplist_single):
    #             subnet_segment.add(iplist_single)
    # return subnet_segment

def es_index(doc):
    result = es.index(
        index= 'alert-{}'.format(datetime.datetime.now().strftime('%Y-%m-%d')),
        doc_type= 'netflow_v9',
        body= doc
    )
    time1 = format(datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
    print (time1)
    print("insert done")
    return result

def insert_result():
    res = list(get_es_ip('tcp-2018-07-26', 1532534400000, 1532620799999, 'sip'))
    doc = {}
    # doc['level'] = 'info'
    doc['type'] = 'sip'
    doc['subnet_segment_count'] = len(res)
    doc['subnet_segment'] = res
    #
    doc['desc_type '] = '[sip] zhaowei'
    doc['@timestamp'] = datetime.datetime.now()
    doc['index'] = 'tcp-*'
    result = es_index(doc)
    return result
'''
def get_all_file(path):
    if(os.path.exists(path)):
        filelist = os.listdir(path)
        return filelist
'''


if __name__ == "__main__":
    res = get_es_ip('tcp-2018-07-30',1532913604525,1532914504525,'sip')
    ret = insert_result()
    print(res)
    print(ret)
