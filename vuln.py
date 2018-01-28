#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Kali-Team'
import psycopg2
import argparse
import json
from verify_vuln import *

parser = argparse.ArgumentParser(description="Kali-Team Acunetix Vulnerabilities")
parser.add_argument('--severity', '-s', action='store', help='severity')#按等级查询
parser.add_argument('--target', '-t', action='store', help='target_id')#按目标ID查询
parser.add_argument('--name', '-n', action='store', help='vuln_name')#按漏洞名称查询
parser.add_argument('--url', '-u', action='store', help='url')#按主机域名查询
parser.add_argument('--raw', '-r', action='store', help='raw')#按请求数据查询

conn = psycopg2.connect(database="wvs",user="wvs",password="wvs",host="localhost",port="35432")#连接数据库
cur = conn.cursor()


def print_info(sql_line):#查询并返回有用漏洞信息。
    cur.execute(sql_line)
    rows = cur.fetchall()
    for i in rows:
        raw = i[0]#完整的http请求
        name = i[1]#漏洞的类型
        attack_vector = i[2]#攻击的payload
        details = i[3]#漏洞的攻击详情
#--下面的判断漏洞类型，再发送到验证漏洞的工具
        if name == "Blind SQL Injection":
            try:
                details = json.loads(details)['orig_value']
                to_sqlmap(raw,attack_vector,details)
            except Exception as e:
                print(e)
        elif name == "Cross site scripting":
            to_brutexss(raw,attack_vector)
            pass
        else:
            pass

args = parser.parse_args()
def main():#判断参数，按照参数进行构造SQL语句
    sql_line = "SELECT request,name,attack_vector,details FROM target_vulns"
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
    if args.raw:
        if "WHERE" not in sql_line:
            sql_line = sql_line + " WHERE request LIKE '"+"%"+args.raw+"%"+"'"
        else:
            sql_line = sql_line + " AND request LIKE '"+"%"+args.raw+"%"+"'"
    print_info (sql_line)
if __name__ == '__main__':
    main()
conn.commit()
cur.close()
conn.close()