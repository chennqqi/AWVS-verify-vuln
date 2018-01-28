# Acunetix11-API-Documentation

### Header设置:
headers=headers,timeout=30,verify=False
```
X-Auth: API-KEY
Content-type: application/json
```

### 所有目标信息:

```
请求的方式:GET 
URL: /api/v1/targets
```
### 添加目标接口:

```
请求的方式:POST 
URL: /api/v1/targets
```
Data:
```
{"address":"http://192.168.220.134/","description":"xxxx","criticality":"10"}
```

# 扫描设置
#### 扫描速度(Scan Speed):
```
请求的方式:PATCH 
URL: /api/v1/targets/{target_id}/configuration
```
Data:
```
{"scan_speed":"sequential"} #slow/moderate/fast
```
#### 登录设置(Site Login)
***网站登录设置***
```
请求的方式: PATCH 
URL: /api/v1/targets/{target_id}/configuration
```
Data:
```
{"login":{"kind":"automatic","credentials":{"enabled":True,"username":"admin","password":"123"}}}
```
#### 代理设置(Proxy Server):
```
请求的方式:PATCH 
URL: /api/v1/targets/{target_id}/configuration
```
Data:
```
{"proxy":{"enabled":True,"address":"127.0.0.1","protocol":"http","port":1080}}


UA {"user_agent":"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"}
```
### 添加扫描:
```
请求的方式:POST
URL: /api/v1/scans
```
Data:
```
{"target_id":target_id,"profile_id":profile_id,"schedule":{"disable":False,"start_date":None,"time_sensitive":False}}

```
### 获取所有扫描状态:
```
请求的方式:GET 
URL: /api/v1/scans
```
### 获取所有漏洞信息
```
Method:GET 
URL: /api/v1/vulnerabilities?q=status:open
```
### 获取单个漏洞信息
```
Method:GET 
URL: api/v1/vulnerabilities/{vuln_id}
```
### 删除目标接口:
```
请求的方式:DELETE
URL: /api/v1/targets/{target_id}
```
http://www.xihaomei.com:9200/
https://www.acunetix.com/vulnerability-scanner/free-manual-pen-testing-tools/

C:\ProgramData\Acunetix 11\shared\scans
