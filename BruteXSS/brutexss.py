#!/usr/bin/python
# -*- coding: utf-8 -*-
#!Cross-Site Scripting Bruteforcer
#!Author: Shawar Khan
#!Site: https://shawarkhan.com

from string import whitespace
import httplib
import argparse
import urllib
import socket
import urlparse
import os
import sys
import time
from colorama import init , Style, Back,Fore
import mechanize
import httplib


parser = argparse.ArgumentParser(description="Kali-Team Acunetix Vulnerabilities")

parser.add_argument('--method', '-m', action='store', help='method')#请求的类型，get post 和没有参数p
parser.add_argument('--url', '-u', action='store', help='url')
parser.add_argument('--wordlist', '-w', action='store', help='wordlist')#字典，默认目录下的wordlist.txt
parser.add_argument('--data', '-d', action='store', help='data')#post 提交的数据

args = parser.parse_args()
if args.wordlist:
	wordlist = args.wordlist
else:
	wordlist = sys.path[0]+'/wordlist.txt'
if args.method:
	methodselect = args.method
else:
	methodselect = "g"
if args.url:
	site = args.url
else:
	print args
	exit()
if args.data:
	param = args.data


init()
banner = """                                                                                       
 BruteXSS - Cross-Site Scripting BruteForcer
 Author: Shawar Khan - https://shawarkhan.com 
 Kali-Team Acunetix Vulnerabilities
"""

def brutexss():
	print banner
	grey = Style.DIM+Fore.WHITE
	def wordlistimport(file,lst):
		try:
			with open(file,'r') as f: #Importing Payloads from specified wordlist.
				print(Style.DIM+Fore.WHITE+"[+] Loading Payloads from specified wordlist..."+Style.RESET_ALL)
				for line in f:
					final = str(line.replace("\n",""))
					lst.append(final)
		except IOError:
			print(Style.BRIGHT+Fore.RED+"[!] Wordlist not found!"+Style.RESET_ALL)

	def complete(p,r,c,d):
		print("[+] Bruteforce Completed.")
	def GET():
			try:
				try:
					grey = Style.DIM+Fore.WHITE
					site = args.url #Taking URL
					if 'https://' in site:
						pass
					elif 'http://' in site:
						pass
					else:
						site = "http://"+site
					finalurl = urlparse.urlparse(site)
					urldata = urlparse.parse_qsl(finalurl.query)
					domain0 = '{uri.scheme}://{uri.netloc}/'.format(uri=finalurl)
					domain = domain0.replace("https://","").replace("http://","").replace("www.","").replace("/","")
					print (Style.DIM+Fore.WHITE+"[+] Checking if "+domain+" is available..."+Style.RESET_ALL)
					connection = httplib.HTTPConnection(domain)
					connection.connect()
					print("[+] "+Fore.GREEN+domain+" is available! Good!"+Style.RESET_ALL)
					url = site
					paraname = []
					paravalue = []
					print(grey+"[+] Using Default wordlist..."+Style.RESET_ALL)
					payloads = []
					wordlistimport(wordlist,payloads)
					lop = str(len(payloads))
					grey = Style.DIM+Fore.WHITE
					print(Style.DIM+Fore.WHITE+"[+] "+lop+" Payloads loaded..."+Style.RESET_ALL)
					print("[+] Bruteforce start:") 
					o = urlparse.urlparse(site)
					parameters = urlparse.parse_qs(o.query,keep_blank_values=True)
					path = urlparse.urlparse(site).scheme+"://"+urlparse.urlparse(site).netloc+urlparse.urlparse(site).path
					for para in parameters: #Arranging parameters and values.
						for i in parameters[para]:
							paraname.append(para)
							paravalue.append(i)
					total = 0
					c = 0
					fpar = []
					fresult = []
					progress = 0
					for pn, pv in zip(paraname,paravalue): #Scanning the parameter.
						fpar.append(str(pn))
						for x in payloads: #
							validate = x.translate(None, whitespace)
							if validate == "":
								progress = progress + 1
							else:
								sys.stdout.flush()
								progress = progress + 1
								enc = urllib.quote_plus(x)
								data = path+"?"+pn+"="+pv+enc
								page = urllib.urlopen(data)
								sourcecode = page.read()
								if x in sourcecode:
									print(Style.BRIGHT+Fore.RED+"\n[!]"+" XSS Vulnerability Found! \n"+Fore.RED+Style.BRIGHT+"[!]"+" Parameter:\t%s\n"+Fore.RED+Style.BRIGHT+"[!]"+" Payload:\t%s"+Style.RESET_ALL)%(pn,x)
									print(data)
									fresult.append("  Vulnerable  ")
									c = 1
									total = total+1
									progress = progress + 1
									break
								else:
									c = 0
						if c == 0:
							progress = progress + 1
							pass
						progress = 0
					complete(fpar,fresult,total,domain)
				except(httplib.HTTPResponse, socket.error) as Exit:
					print(Style.BRIGHT+Fore.RED+"[!] Site "+domain+" is offline!"+Style.RESET_ALL)
			except(KeyboardInterrupt) as Exit:
				print("\nExit...")
	def NO_P():
			try:
				try:
					grey = Style.DIM+Fore.WHITE
					site = args.url #Taking URL
					if 'https://' in site:
						pass
					elif 'http://' in site:
						pass
					else:
						site = "http://"+site
					finalurl = urlparse.urlparse(site)
					urldata = urlparse.parse_qsl(finalurl.query)
					domain0 = '{uri.scheme}://{uri.netloc}/'.format(uri=finalurl)
					domain = domain0.replace("https://","").replace("http://","").replace("www.","").replace("/","")
					print (Style.DIM+Fore.WHITE+"[+] Checking if "+domain+" is available..."+Style.RESET_ALL)
					connection = httplib.HTTPConnection(domain)
					connection.connect()
					print("[+] "+Fore.GREEN+domain+" is available! Good!"+Style.RESET_ALL)
					url = site
					print(grey+"[+] Using Default wordlist..."+Style.RESET_ALL)
					payloads = []
					wordlistimport(wordlist,payloads)
					lop = str(len(payloads))
					grey = Style.DIM+Fore.WHITE
					print(Style.DIM+Fore.WHITE+"[+] "+lop+" Payloads loaded..."+Style.RESET_ALL)
					print("[+] Bruteforce start:") 
					o = urlparse.urlparse(site)
					parameters = urlparse.parse_qs(o.query,keep_blank_values=True)
					path = urlparse.urlparse(site).scheme+"://"+urlparse.urlparse(site).netloc+urlparse.urlparse(site).path
					#print path
					total = 0
					c = 0
					fpar = []
					fresult = []
					progress = 0
					for x in payloads: #
						validate = x.translate(None, whitespace)
						if validate == "":
							progress = progress + 1
						else:
							sys.stdout.flush()
							progress = progress + 1
							#print(path+x)
							page = urllib.urlopen(path+x)
							sourcecode = page.read()
							#print sourcecode
							if x in sourcecode:
								print(Style.BRIGHT+Fore.RED+"\n[!]"+" XSS Vulnerability Found! \n"+Fore.RED+Style.BRIGHT+"[!]"+" Parameter:\t%s\n"+Fore.RED+Style.BRIGHT+"[!]"+" Payload:\t%s"+Style.RESET_ALL)%("pn",x)
								print(path+x)
								fresult.append("  Vulnerable  ")
								c = 1
								total = total+1
								progress = progress + 1
								break
							else:
								c = 0
					if c == 0:
						progress = progress + 1
						pass
					progress = 0
					#complete(fpar,fresult,total,domain)
				except(httplib.HTTPResponse, socket.error) as Exit:
					print(Style.BRIGHT+Fore.RED+"[!] Site "+domain+" is offline!"+Style.RESET_ALL)
			except(KeyboardInterrupt) as Exit:
				print("\nExit...")
	def POST():
		try:
			try:
				try:
					br = mechanize.Browser()
					br.addheaders = [('User-agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11')]
					br.set_handle_robots(False)
					br.set_handle_refresh(False)
					site = args.url #Taking URL
					if 'https://' in site:
						pass
					elif 'http://' in site:
						pass
					else:
						site = "http://"+site
					finalurl = urlparse.urlparse(site)
					urldata = urlparse.parse_qsl(finalurl.query)
					domain0 = '{uri.scheme}://{uri.netloc}/'.format(uri=finalurl)
					domain = domain0.replace("https://","").replace("http://","").replace("www.","").replace("/","")
					print (Style.DIM+Fore.WHITE+"[+] Checking if "+domain+" is available..."+Style.RESET_ALL)
					connection = httplib.HTTPConnection(domain)
					connection.connect()
					print("[+] "+Fore.GREEN+domain+" is available! Good!"+Style.RESET_ALL)
					path = urlparse.urlparse(site).scheme+"://"+urlparse.urlparse(site).netloc+urlparse.urlparse(site).path
					url = site
					param = args.data #Taking URL
					if  wordlist == "":
						print("[+] Using Default wordlist...")
					else:
						pass
					payloads = []
					wordlistimport(wordlist,payloads)
					lop = str(len(payloads))
					grey = Style.DIM+Fore.WHITE
					print(Style.DIM+Fore.WHITE+"[+] "+lop+" Payloads loaded..."+Style.RESET_ALL)
					print("[+] Bruteforce start:")
					params = "http://www.site.com/?"+param
					finalurl = urlparse.urlparse(params)
					urldata = urlparse.parse_qsl(finalurl.query)
					o = urlparse.urlparse(params)
					parameters = urlparse.parse_qs(o.query,keep_blank_values=True)
					paraname = []
					paravalue = []
					for para in parameters: #Arranging parameters and values.
						for i in parameters[para]:
							paraname.append(para)
							paravalue.append(i)
					fpar = []
					fresult = []
					total = 0
					progress = 0
					pname1 = [] #parameter name
					payload1 = []
					for pn, pv in zip(paraname,paravalue): #Scanning the parameter.
						fpar.append(str(pn))
						for i in payloads:
							validate = i.translate(None, whitespace)
							if validate == "":
								progress = progress + 1
							else:
								progress = progress + 1
								sys.stdout.flush()
								pname1.append(pn)
								payload1.append(str(i))
								d4rk = 0
								for m in range(len(paraname)):
									d = paraname[d4rk]
									d1 = paravalue[d4rk]
									tst= "".join(pname1)
									tst1 = "".join(d)
									if pn in d:
										d4rk = d4rk + 1
									else:
										d4rk = d4rk +1
										pname1.append(str(d))
										payload1.append(str(d1))
								data = urllib.urlencode(dict(zip(pname1,payload1)))
								r = br.open(path, data)
								sourcecode =  r.read()
								pname1 = []
								payload1 = []
								if i in sourcecode:
									print(Style.BRIGHT+Fore.RED+"\n[!]"+" XSS Vulnerability Found! \n"+Fore.RED+Style.BRIGHT+"[!]"+" Parameter:\t%s\n"+Fore.RED+Style.BRIGHT+"[!]"+" Payload:\t%s"+Style.RESET_ALL)%(pn,i)
									print(path,data)
									fresult.append("  Vulnerable  ")
									c = 1
									total = total+1
									progress = progress + 1
									break
								else:
									c = 0
						if c == 0:
							progress = progress + 1
							pass
						progress = 0
					complete(fpar,fresult,total,domain)
				except(httplib.HTTPResponse, socket.error) as Exit:
					print(Style.BRIGHT+Fore.RED+"[!] Site "+domain+" is offline!"+Style.RESET_ALL)
			except(KeyboardInterrupt) as Exit:
				print("\nExit...")
		except (mechanize.HTTPError,mechanize.URLError) as e:
			print(Style.BRIGHT+Fore.RED+"\n[!] HTTP ERROR! %s %s"+Style.RESET_ALL)%(e.code,e.reason)
	try:
		if methodselect == 'g':#GET请求
			GET()
		elif methodselect == 'p':#POST请求
			POST()
		elif methodselect == 'n':#没有带参数的请求
			NO_P()
		else:
			print("[!] Incorrect method selected.")
	except(KeyboardInterrupt) as Exit:
		print("\nExit...")

brutexss()
