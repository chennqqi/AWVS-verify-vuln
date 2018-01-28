#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Kali-Team'
import psycopg2
import argparse
#88109129-8723-4dde-9ca9-043b1be50df1
parser = argparse.ArgumentParser(description="Kali-Team Acunetix Vulnerabilities")
parser.add_argument('--target', '-t', action='store', help='target_id')#按目标ID删除
args = parser.parse_args()
conn = psycopg2.connect(database="wvs",user="wvs",password="wvs",host="localhost",port="35432")#连接数据库
cur = conn.cursor()
tables =['target_vulns_stats','scan_sessions','scans','target_configuration','target_vulns','target_vulns_stats','targets']
for x in tables:
    l = '''DELETE FROM "public"."{}" WHERE ("target_id"='{}');'''.format(x,args.target)
    try:
        cur.execute(l)
        rows = cur.fetchall()
        print rows
    except:
        print "Error"

conn.commit()
cur.close()
conn.close()