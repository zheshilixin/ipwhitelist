# -*- coding:utf-8 -*-

#引入需要的模块
import urllib #用于进行中文编码
import urllib2  #用于进行爬虫核心处理

#定义一个函数，用于爬取对应的数据
def load_url(url,file_name):
    '''
    作用：针对指定的url地址，进行数据的获取
    :param url: 要爬取数据的具体url地址
    :param file_name: 要保存的文件名称；在当前函数中，只做提示使用
    :return: 爬取的数据
    '''
    print('开始爬取%s的内容'%file_name)
    #爬取程序
    my_headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.104 Safari/537.36',
    }
    request = urllib2.Request(url,headers=my_headers)
    content = urllib2.urlopen(request).read()
    print('爬取%s的内容完成！'%file_name)
    return content

#定义一个函数，用于保存数据
def save_data(data,file_name):
    '''
    作用：主要用于进行数据存储
    :param data: 要存储的数据
    :param file_name: 要存储的文件名称
    :return: 无
    '''
    print('开始保存%s的内容'%file_name)

    with open(file_name,'w') as f:
        f.write(data)
    print('保存%s的内容完成！'%file_name)


#定义函数，进行爬虫的核心处理功能
def spider(url,kw,begin,end):
    '''
    用于进行核心爬虫功能的调度
    :param url: 要爬取的地址
    :param kw: 贴吧名称
    :param begin: 起始页码
    :param end: 结束页码
    :return: 无
    '''
    for page in range(begin,end+1):
        #计算需要的页码
        pn = (page-1)*50
        #进行kw参数的编码
        kw = urllib.urlencode({'kw':kw})
        #拼接url地址
        full_url = url + kw +'&pn=' +str(pn)
        #定义一个保存文件的名称
        file_name = '网页'+str(page) +'.html'
        #开始爬取数据
        html=load_url(full_url,file_name)
        #保存数据到文件
        save_data(html,file_name)

#主程序运行入口
if __name__ == '__main__':
    #用户输入相关数据
    url='http://tieba.baidu.com/f?'
    kw = raw_input('请输入要爬取的贴吧名称：')
    begin = int(raw_input('请输入开始页码：'))
    end = int(raw_input('请输入结束页码：'))

    #调用爬虫开始执行
    spider(url,kw,begin,end)