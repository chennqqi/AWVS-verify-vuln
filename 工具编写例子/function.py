#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Kali-Team'
import hashlib

desktop = r'C:\Users\Kali-Team\Desktop'
cut = "\n"+"-"*30+"\n"

def w_file(fname,text,mode='a'):#写文件
    file = open(fname, mode=mode)
    file.write(text)
    file.close()

def get_header(h_raws,key):#把请求数据转字典
    v_dic={}
    H = h_raws.index("HTTP/1.1")
    key_value = h_raws[H+len("HTTP/1.1\n"):].split('\n')
    for x in key_value:
        if len(x.split(': ')) == 2:
            v_dic[x.split(': ')[0]]=x.split(': ')[1].replace('\r', '')

    v_dic["method"] = h_raws[0:H][0:4].replace(' ', '')#请求方式
    v_dic["url"] = h_raws[0:H][4:]
    A = h_raws.index("Accept: */*")
    if h_raws[A+len("Accept: */*"):].replace('\n', ''):
        v_dic["data"] = h_raws[A+len("Accept: */*"):].replace('\n', '')
    if key in v_dic.keys():
        return v_dic[str(key)]
    else:
        return ""

def get_md5(str):  
    raw_md5 = hashlib.md5()#获取一个MD5的加密算法对象  
    raw_md5.update(str) #得到MD5消息摘要  
    raw_md5_Digest = raw_md5.hexdigest()#以16进制返回消息摘要，32位  
    return raw_md5_Digest

def reports(v_name,raw,info):#写报告的，漏洞类型，RAW，信息
    if 'Error' in info:#验证失败的，保存到文件，等人工验证
        w_file(desktop+"/fail.md","\n## "+v_name+cut,'a')
        w_file(desktop+"/fail.md","### RAW:\n"+'```\n'+raw+'\n```','a')
        w_file(desktop+"/fail.md","\n### info:\n"+'```\n'+info+"\n```",'a')
    else:#漏洞验证成功了的
        print("Found a "+v_name)
        w_file(desktop+"/vuln.md","\n## "+v_name+cut,'a')
        #w_file(desktop+"/vuln.md","### RAW:\n"+'```\n'+raw+'\n```','a')
        w_file(desktop+"/vuln.md","\n### info:\n"+'```\n'+info+"\n```",'a')