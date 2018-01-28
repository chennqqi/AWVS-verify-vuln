#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
#设置主机和api-key
tarurl = "https://localhost:3443/api/v1/"
apikey="1986ad8c0a5b3df4d7028d5f3c06e936c3809dec5b3f94fb09d521c5fb648faee"
#构造请求头，api身份验证
headers = {"X-Auth":apikey,"content-type": "application/json"}

r ={
"H":'11111111-1111-1111-1111-111111111112',    #High Risk Vulnerabilities
"W":'11111111-1111-1111-1111-111111111115',    #Weak Passwords
"C":'11111111-1111-1111-1111-111111111117',    #Crawl Only
"X":'11111111-1111-1111-1111-111111111116',    #Cross-site Scripting Vulnerabilities
"S":'11111111-1111-1111-1111-111111111113',    #SQL Injection Vulnerabilities
"F":'11111111-1111-1111-1111-111111111111'     #Full Scan
}

def add_target(url):
    try:
        data = {"address":url,"description":"api","criticality":"10"}
        responses = requests.post(tarurl+"targets",data=json.dumps(data),headers=headers,verify=False)
        return json.loads(responses.text)['target_id']
    except Exception as e:
        print(e)



def del_target(target_id):
    responses = requests.delete(tarurl+"targets/"+target_id,headers=headers,verify=False)
    print(responses.status_code)

def config(target_id,data):
    try:
        responses = requests.patch(tarurl+"targets/"+target_id+"/configuration",data=json.dumps(data),headers=headers,verify=False)
        print(responses.status_code)
    except Exception as e:
        print(e)

def set_speen(id,speen):
    data = {"scan_speed":speen} #slow/moderate/fast
    config(id,data)
def set_login(id,username,password):
    data = {"login":{"kind":"automatic","credentials":{"enabled":True,"username":username,"password":password}}}
    config(id,data)
def set_proxy(id,ip,port):
    data = {"proxy":{"enabled":True,"address":ip,"protocol":"http","port":port}}
    config(id,data)

def start_scan(target_id,profile_id):
    try:
        data = {"target_id":target_id,"profile_id":profile_id,"schedule":{"disable":False,"start_date":None,"time_sensitive":False}}
        responses = requests.post(tarurl+"scans",data=json.dumps(data),headers=headers,verify=False)
    except Exception as e:
        print(e)

def GO(url):
    ID=add_target(url)
    set_speen(ID,"slow")
    set_proxy(ID,"127.0.0.1",1080)
    set_login(ID,"admin","password")
    start_scan(ID,r["F"])

for x in open("url.txt"):
    GO(x.replace("\n",""))