# -*- coding: utf-8 -*-
from elasticsearch import Elasticsearch
import time
from datetime import datetime
import subprocess
import shlex
import commands

es = Elasticsearch(['192.168.10.65'], port=9200)

def execute_command(cmdstring,cwd=None, timeout=None,shell=False):
    '''
    执行一个shell命令
        封装了subprocess的Popen方法，支持超时判断，支持读取stdout和stderr
    参数：
    :param cmdstring:
    :param cwd: 运行命令时更改路径，如果被设定，子进程会直接先更改当前路径到cwd
    :param timeout: 超时时间，秒，支持小数，精度0.1秒
    :param shell: 是否通过shell运行
    :return: return_code
    '''
    if shell:
        cmdstring_list = cmdstring
    else:
        cmdstring_list = shlex.split(cmdstring)
    if timeout:
        end_time = datetime.datetime.now()+datetime.timedelta(seconds=timeout)
    # 没有指定标准输出和错误输出的管道，因此会打印到屏幕上；
    sub = subprocess.Popen(cmdstring_list, cwd=cwd, stdin=subprocess.PIPE, shell=shell, bufsize=4096)
    # subprocess.poll()方法：检查子进程是否结束了，如果结束了，设定并返回码，放在subprocess.returncode变量中
    while sub.poll() is None:
        time.sleep(0.1)
        if timeout:
            if end_time <= datetime.datetime.now():
                raise Exception("Timeout: %s"%cmdstring)

    return str(sub.returncode)

def get_es_data(index,gte,lte):
    search_option3 = \
    {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "*",
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
                        "1": "desc"
                    }
                },
                "aggs": {
                    "1": {
                        "sum": {
                            "field": "byte"
                        }
                    }
                }
            }
        }
    }
    search_result = es.search(index=index, body=search_option3)
    clean_search_result = search_result['aggregations']['2']['buckets']
    # ip = []
    # byte = []
    # for ip,bytes in clean_search_result:
    #     ip.append(ip['key'])
    #     byte.append(bytes['key'])
    return clean_search_result

def get_nf_data(ago_year,ago_mouth,ago_day,ago_hour,ago_min,time_year,time_mouth,time_day,time_hour,time_min):
    options = '%sa %da %pkt'
    root = '/home/stevens/metadata/tcp'+'/'+time_year+'/'+time_mouth+'/'+time_day+'/'+time_hour
    root1 = '/home/stevens/metadata/tcp' + '/' + ago_year + '/' + ago_mouth + '/' + ago_day + '/' + ago_hour+'/'
    root2 = '/home/stevens/metadata/tcp' + '/' + time_year + '/' + time_mouth + '/' + time_day + '/' + time_hour+'/'
    start = 'nfcapd_tcp.'+ago_year+ago_mouth+ago_day+ago_hour+ago_min+'00'
    end = 'nfcapd_tcp.'+time_year+time_mouth+time_day+time_hour+time_min+'00'
    #注意： -R 无法跨文件夹读取数据 -M跨文件夹读取数据
    #cmd = 'nfdump -R ' + root + '/' + start + ':' + end + ' -N -p 1,4,10,13 -o "fmt: %sa %byt" -A srcip'
    cmd = 'nfdump -M ' + root1 + ':' + root2 + ' -R ' + start + ':' + end + ' -N -p 1,4,10,13 -o "fmt: %sa %byt" -A srcip'
    nfdump = commands.getstatusoutput(cmd)
    return nfdump

def get_sqlalert_data():
    #注意：sqlalert代码执行条件需要在rules文件夹下，因此python也需要放在该目录下执行
    cmd = '/etc/sqlalert-1.0.4/bin/sqlalert -e . -t /etc/sqlalert-1.0.4/rules/test/compare3data.rule'
    output = commands.getstatusoutput(cmd)
    return output
'''
def agg_sql_data():
    agg_data = {}
    with open('/home/data/sql_data.txt') as file:
        for line in file:
            list_line = line.strip().split()
            key = list_line[0]
            value = list_line[2]
            oldValue = 0
            if(agg_data.has_key(key)):
                oldValue=agg_data[key]
                del(agg_data[key])
            agg_data[key] = int(oldValue)+int(value)
    return agg_data
'''
def agg_sql_data(path,col1,col2):
    dfile = open(path)
    index1 = dfile.readline().split().index(col1)
    index2 = dfile.readline().split().index(col2)
    data1  = [str(line.split()[index1]) for line in dfile]
    data2  = [float(line.split()[index2]) for line in dfile]
    dfile.close()
    return data1, data2

def get_time():
    now = time.time()
    min_now = time.strftime("%Y-%m-%d-%H-%M",time.localtime(now))
    min_ago = time.strftime('%Y-%m-%d-%H-%M', time.localtime(now - 300))
    time_list = []
    ago_list = []
    min_now_split = min_now.split('-')
    min_ago_split = min_ago.split('-')
    for key in min_now_split:
        time_list.append(key)
    for key in min_ago_split:
        ago_list.append(key)
    __time_year__ = time_list[0]
    time_mout = time_list[1]
    time_day = time_list[2]
    time_hour = time_list[3]
    time_min = time_list[4]

    ago_year = ago_list[0]
    ago_mout = ago_list[1]
    ago_day = ago_list[2]
    ago_hour = ago_list[3]
    ago_min = ago_list[4]

if __name__ == '__main__':
    start = time.clock()
    now = time.time()
    min_now = time.strftime("%Y-%m-%d-%H-%M", time.localtime(now))
    min_ago = time.strftime('%Y-%m-%d-%H-%M', time.localtime(now - 300))
    time_list = []
    ago_list = []
    min_now_60 = time.strftime("%Y-%m-%d-%H-%M", time.localtime(now-60))
    min_ago_60 = time.strftime("%Y-%m-%d-%H-%M", time.localtime(now-360))
    min_now_split = min_now.split('-')
    min_ago_split = min_ago.split('-')
    for key in min_now_split:
        time_list.append(key)
    for key in min_ago_split:
        ago_list.append(key)
    '''
    time_year = time_list[0]
    time_mouth = time_list[1]
    time_day = time_list[2]
    time_hour = time_list[3]
    time_min = time_list[4]

    ago_year = ago_list[0]
    ago_mouth = ago_list[1]
    ago_day = ago_list[2]
    ago_hour = ago_list[3]
    ago_min = ago_list[4]
    '''
    index = 'tcp-'+time_list[0]+'-'+time_list[1]+'-'+time_list[2]
    gte = int(round(now-300)*1000)
    lte = int(round(now)*1000)

    es_data  = str(get_es_data(index,gte,lte))
    #nf_data = str(get_nf_data(ago_list[0], ago_list[1], ago_list[2], ago_list[3], ago_list[4], time_list[0], time_list[1], time_list[2], time_list[3], time_list[4]))
    sql_data = str(get_sqlalert_data())
    #time.sleep(60)
    nf_data = str(
        get_nf_data(ago_list[0], ago_list[1], ago_list[2], ago_list[3], ago_list[4], time_list[0], time_list[1],
                    time_list[2], time_list[3], time_list[4]))

    print ("get data from es    "+ es_data)
    print ('get data from nfdump    ' + nf_data)
    print ('get data from sqlalert  ' + sql_data)
    end = time.clock()
    print('Running time: %s Seconds' % (end - start))
