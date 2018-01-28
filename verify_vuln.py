#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Kali-Team'

import os
import urllib
import requests
import re
from function import *
#工具的路径
sql_path = os.path.join(os.path.expanduser("~"), 'Desktop')+"\sql"#在桌面新建一个sql的文件夹就可以了
sqlmap_path = r'D:\PentestBox\sqlmap'#这是你的sqlmap的路径
brutexss_path = r"C:\Users\Kali-Team\Desktop\acunetix-api\BruteXSS"#BruteXSS的路径
cut = "\n"+"-"*30+"\n"
try:
    os.remove(desktop+"/vuln.md")
    os.remove(desktop+"/fail.md")
except Exception as e:
    pass

def to_sqlmap(raws,attack_vector,details):#发送raw到sqlmap
    if raws:
        #print get_md5(raws)#以MD5为文件名
        raws = urllib.unquote(raws).replace(attack_vector,details)
        file_name = sql_path +'/'+ get_md5(raws)+'.txt'
        w_file(file_name,raws,"w")
        line = 'python '+sqlmap_path+'/sqlmap.py -r '+file_name+" --batch"
        Payload = os.popen(line).read()
        if "Payload:" in Payload:
            reports('Blind SQL Injection',raws,Payload[Payload.index("---"):]+"\n"+line)
        else:
            for filenames in os.listdir(sqlmap_path+r'\tamper\kali'):#列出sqlmap的tamper，再跑一遍
                line = 'python '+sqlmap_path+'/sqlmap.py -r '+sql_path +'\\'+ get_md5(raws)+'.txt '+" --batch --tamper="+filenames
                print(line)
                Payload = os.popen(line).read()
                if "Payload:" in Payload:
                    reports('Blind SQL Injection',raws,Payload[Payload.index("---"):]+"\n"+line)
                    return ""
            reports('Blind SQL Injection',raws,'Error')

def to_brutexss(raws,attack_vector):#发送url到BruteXSS
    Host = "http://"+get_header(raws,"Host")#获取主机地址
    Url = urllib.unquote(get_header(raws,"url")).replace(' ', '')
    method = get_header(raws,"method")#请求方式GET or POST
    data = get_header(raws,"data")
    if attack_vector:#判断是否存在攻击的payload，不为空就把payload替换成其他字符,可以提高成功率
        Url = urllib.unquote(Url).replace(urllib.unquote(attack_vector).replace(' ', ''),attack_vector[0])
#判断请求的类型----
    if method == "POST":
        Payload = os.popen('python '+brutexss_path+'/brutexss.py -u '+'"'+Host+Url+'"'+' -m p -d '+data )
    else:#下面的是GET请求
        if "?" in raws:#判断请求是否带参数
            Payload = os.popen('python '+brutexss_path+'/brutexss.py -u '+'"'+Host+Url+'"').read()
            if "XSS Vulnerability Found!" in Payload:#判断执行的返回是否测试出来漏洞
                Payload = Host+Url+"\n"+ Payload[Payload.index("XSS Vulnerability Found!"):]
                reports('Cross site scripting',raws,Payload+cut)
            else:#如果工具验证失败，把payload里的随机字符用正则替换prompt(1)，方便手工验证
                Url = get_header(raws,"url")
                Url = re.sub(r"([0-9a-zA-Z]{4}\([0-9]{4}\))","prompt(1)",Url)
                reports('Cross site scripting',raws,"Error:\n"+Host+Url)
        else:#请求不带参数，直接加payload测试
            Payload = os.popen('python '+brutexss_path+'/brutexss.py -u '+Host+Url+' -m n').read()
            if "XSS Vulnerability Found!" in Payload:
                Payload = Host+Url+"\n"+ Payload[Payload.index("XSS Vulnerability Found!"):]
                reports('Cross site scripting',raws,Payload+cut)
            else:
                Url = get_header(raws,"url")
                Url = re.sub(r"([0-9a-zA-Z]{4}\([0-9]{4}\))","prompt(1)",Url)
                reports('Cross site scripting',raws,"Error:\n"+Host+Url)
