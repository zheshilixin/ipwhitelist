import ConfigParser
import re,datetime,os
import blacklist_tools

cp = ConfigParser.ConfigParser()
cp.read("blacklist_match.conf")
section = cp.sections()
# print section
def get_func():
    parse_blacklist_key = cp.options("parse_blacklist")
    #function module
    moudle_func = cp.get("parse_blacklist", parse_blacklist_key[0])
    moudle_list = moudle_func.split(',')
    # print moudle_list
    moudle_name = {}
    for temp in moudle_list:
        fname,ftimes=temp.split(":")
        fname = fname.strip()
        # as a dict: key is filename,value is the update frequency
        moudle_name[fname]=ftimes
    return moudle_name

def get_store_path():
    #source_data_path
    source_store_path_key = cp.options('source_store_path')
    source_store_path = []
    for temp in source_store_path_key:
        source_store_path.append(cp.get('source_store_path', temp))
    return source_store_path


def get_ES_info():
    # ES information
    source_store_path_key=cp.options("ES_info")
    #value=cp.get(sectionName,keyword)
    server=cp.get('ES_info',source_store_path_key[0])
    dport=cp.get('ES_info',source_store_path_key[1])
    indx=cp.get('ES_info',source_store_path_key[2])
    aggs_name=cp.get('ES_info',source_store_path_key[3])
    return server,dport,indx,aggs_name

def getCheckDeltatime():
    #check frequency
    timekey1=cp.options("delta_time_check")
    times=cp.getint("delta_time_check",timekey1[0])
    deltatime=datetime.timedelta(minutes=times)
    timekey2=cp.options("frequency")
    starttime=cp.get("frequency",timekey2[0])
    return deltatime,starttime

def get_module_path():
    #source_data_path
    module_path_key = cp.options('blacklist_moudle_path')
    # print module_path_key
    module_path = []
    for temp in module_path_key:
        module_path.append(cp.get('blacklist_moudle_path', temp))
    return module_path

def get_method():
    # get subnet method
    source_store_path_key = cp.options("subnet_methods")
    # value=cp.get(sectionName,keyword)
    flg_lpm = cp.getint('subnet_methods', source_store_path_key[0])
    flg_full = cp.getint('subnet_methods', source_store_path_key[1])
    return flg_lpm,flg_full

def get_self_filelist(keywords):
    # optionname must be whitelist or blacklist or defaultlist
    mylog=blacklist_tools.getlog()
    optionname='self_'+keywords+'_path'
    try:
        source_store_path_key=cp.options(optionname)
        #value=cp.get(sectionName,keyword)
        flg=cp.getint(optionname,source_store_path_key[0])
        bpath=cp.get(optionname,source_store_path_key[1])
        path=get_store_path()[1]+bpath+os.path.sep
        return flg,path
    except Exception,e:
        mylog.error('config file error!')
        return 0,''



# print cp.sections
#cun period
#############################################################################################################################
# frequency_key = cp.options(sections[3])
# frequency = []
# for temp in frequency_key:
#     frequency.append(cp.get('frequency', temp))
#
# # print frequency
# regex1=re.compile(r'\d+')
# regex2=re.compile(r'[a-zA-Z]+')
# period_num = regex1.findall(frequency[1])[0]
# period_scale = regex2.findall(frequency[1])[0]
# def export_period():
#     if period_scale == 's'or period_scale == 'S' :
#         period  = datetime.timedelta(seconds = int(period_num))
#     elif period_scale == 'm'or period_scale == 'M':
#         period = datetime.timedelta(minutes = int(period_num))
#     elif period_scale == 'd' or period_scale == 'D':
#         period = datetime.timedelta(days = int(period_num))
#     return period
#############################################################################################################################