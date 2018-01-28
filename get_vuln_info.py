#!/usr/bin/python
# -*- coding: utf-8 -*-
#易语言用,请不要删除或修改
__author__ = 'Kali-Team'
import psycopg2
import argparse
from verify_vuln import *

parser = argparse.ArgumentParser(description="Kali-Team Acunetix Vulnerabilities")
parser.add_argument('--severity', '-s', action='store', help='severity')#按等级查询
parser.add_argument('--target', '-t', action='store', help='target_id')#按目标ID查询
parser.add_argument('--name', '-n', action='store', help='vuln_name')#按漏洞名称查询
parser.add_argument('--url', '-u', action='store', help='url')#按主机域名查询
parser.add_argument('--raw', '-r', action='store', help='raw')#按请求数据查询

conn = psycopg2.connect(database="wvs",user="wvs",password="wvs",host="localhost",port="35432")#连接数据库
cur = conn.cursor()


def print_info(sql_line):
    cur.execute(sql_line)
    rows = cur.fetchall()
    for i in rows:
        url = i[4]
        loc_detail = i[5]
        request = i[12]
        vuln_name = i[19]
        attack_vector = i[22]#下面的输出不要改，不然易语言会匹配不了漏洞信息,如果不用易语言随便改
        print "Vuln_Name:"+vuln_name+"\n","URL:"+url+"\n","attack_name:"+loc_detail+"\n","attack_vector:"+attack_vector+"\n","RAW:\n"+request
        print "-"*50
args = parser.parse_args()

sql_line = "SELECT * FROM target_vulns"

if args.severity:
    if 0 <= int(args.severity) <= 3:
        sql_line = sql_line + " WHERE severity='"+args.severity+"'"

if args.target and len(args.target) == 36:
    if "WHERE" not in sql_line:
        sql_line = sql_line + " WHERE target_id='"+args.target+"'"
    else:
        sql_line = sql_line + " AND target_id='"+args.target+"'"

if args.name:
    if "WHERE" not in sql_line:
        sql_line = sql_line + " WHERE name LIKE '"+"%"+args.name+"%"+"'"
    else:
        sql_line = sql_line + " AND name LIKE '"+"%"+args.name+"%"+"'"
       
if args.url:#url LIKE '"+"%"+url+"%"+"'"
    if "WHERE" not in sql_line:
        sql_line = sql_line + " WHERE url LIKE '"+"%"+args.url+"%"+"'"
    else:
        sql_line = sql_line + " AND url LIKE '"+"%"+args.url+"%"+"'"
if args.raw:#url LIKE '"+"%"+url+"%"+"'"
    if "WHERE" not in sql_line:
        sql_line = sql_line + " WHERE request LIKE '"+"%"+args.raw+"%"+"'"
    else:
        sql_line = sql_line + " AND request LIKE '"+"%"+args.raw+"%"+"'"


print_info (sql_line)

conn.commit()
cur.close()
conn.close()