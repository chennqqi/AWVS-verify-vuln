#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Kali-Team'
import psycopg2
import argparse
conn = psycopg2.connect(database="wvs",user="wvs",password="wvs",host="localhost",port="35432")#连接数据库
cur = conn.cursor()
sql_line = "SELECT * FROM target_vulns"#SELECT request,name,attack_vector,details FROM target_vulns
cur.execute(sql_line)
rows = cur.fetchall()
for i in rows:
    url = i[4]
    loc_detail = i[5]
    request = i[12]
    vuln_name = i[19]
    attack_vector = i[22]
    print(request)


conn.commit()
cur.close()
conn.close()

