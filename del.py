#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Kali-Team'
import psycopg2
import argparse
ID =[]
parser = argparse.ArgumentParser(description="Kali-Team Acunetix Vulnerabilities")
parser.add_argument('--target', '-t', action='store', help='target_id')#°′??±êIDé?3y
parser.add_argument('--end', '-e', action='store_true', help='end')
args = parser.parse_args()
conn = psycopg2.connect(database="wvs",user="wvs",password="wvs",host="localhost",port="35432")#á??óêy?Y?a
cur = conn.cursor()
cur.execute('SELECT target_id FROM targets')
rows = cur.fetchall()

def T(target_id):
    tables =['target_vulns_stats','scan_sessions','scans','target_configuration','target_vulns','target_vulns_stats','targets']
    for x in tables:
        l = '''DELETE FROM "public"."{}" WHERE ("target_id"='{}');'''.format(x,target_id)
        try:
            cur.execute(l)
            rows = cur.fetchall()
        except Exception as e:
            print(e)

if args.end:
    for x in rows:
        if x[0] in ID:
            print(x[0])
        else:
            T(x[0])


if args.target and len(args.target) == 36:
    T(args.target)
conn.commit()
cur.close()
conn.close()
#!易语言调用删除ID的，请不要删除