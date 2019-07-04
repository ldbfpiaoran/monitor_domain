#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
import config
import sql
import os
import logging
import colorlog
import json
from functools import reduce 
import time
import sys
import dns.resolver
import sendwx
import csv
from brutedns import Brutedomain   #  is subdomain3




# sys.setrecursionlimit(10000)
'''
set log this code is Useless
log.debug  is white ,info is green ,warn is yellow ,error is red ,critical  red!
'''
handler = colorlog.StreamHandler()
formatter = colorlog.ColoredFormatter(
    '%(log_color)s%(asctime)s [%(name)s] [%(levelname)s] %(message)s%(reset)s',
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%')
handler.setFormatter(formatter)
log = colorlog.getLogger('findsub')
log.addHandler(handler)
log.setLevel(logging.INFO)

"""
dict 格式  {"subdomain":"","title":"","domain":"","port":"None","ip":"None","htmlsize":"None"}
"""




class start:
    def __init__(self):
        self.config_main = config.Config
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['119.29.29.29']
        self.resolver.timeout = 10   
        self.blacktime = self.config_main.blacktime  #泛解析策略
        self.black_ip = {"114.114.114.114":11,"1.1.1.1":11}  #sql.select_black()     #   泛解析黑名单ip字典
    
    def subscan(self):
        # sendwx.send_data("222")
        scan_domain = sql.select_domain(status=0)[0]
        while True:
            if scan_domain:
                try:
                    filename = self.config_main.name_save_path  +scan_domain+"/" +scan_domain+".txt"
                    other_file = self.config_main.name_save_path +scan_domain+"/" +scan_domain+"_all.log"
                    amass_json = self.config_main.name_save_path +scan_domain+"/" +scan_domain+'.json'
                    self.ini(scan_domain)   #   初始化 随机域名判断泛解析
                    lastid = sql.select_id(scan_domain)
                    # print(lastid)
                    sql.update_status(scan_domain,status=1)
                    os.system("mkdir "+self.config_main.name_save_path  +scan_domain)
                    if not os.path.exists(filename):
                        os.system("subfinder -d {} -o {}".format(scan_domain,filename))
                        log.info("subfinder -d {} -o {}".format(scan_domain,filename))
                    else:
                        log.warn("subfinder is sacned   Please del the file")

                    if not os.path.exists(amass_json):
                        log.info("amass/amass  -r 119.29.29.29 -d {}  -brute -min-for-recursive 3 -do {}".format(scan_domain,amass_json))
                        os.system("amass/amass  -d {}  -brute -w {} -min-for-recursive 3 -do {}".format(scan_domain,self.config_main.amass_dict,amass_json))
                    else:
                        log.warn("amass is sacned   Please del the file")
                    
                    if not os.path.exists(other_file):
                        self.write_ams_sub(scan_domain,filename,amass_json,other_file)
                        
                    log.info("start  subdomain3")
                    # break
                    brute = Brutedomain(domain=scan_domain,level =3,sub_file = self.config_main.sub_dict,speed='high',next_sub_dict = self.config_main.next_sub_dict,realdict = self.config_main.real_subdict )     
                    # domain,level,sub_file,speed,next_sub_dict,other_file
                    brute.run()
                    log.info("total {} domains get at output/{name}/{name}.csv".format(str(brute.found_count),name = scan_domain))
                    sendwx.send_data("total {} domains get at output/{name}/{name}.csv".format(str(brute.found_count),name = scan_domain))
                    self.insert_sub(domain=scan_domain)
                    sql.update_status(scan_domain,status=2)
                except Exception as err:
                    log.error(err)
                    
                if sql.select_id(scan_domain) > lastid:
                    sendwx.send_data("new subdomains alert")
                    sendwx.send_data(sql.select_sub(scan_domain,lastid))
                try:
                    scan_domain = sql.select_domain(status=0) #  select status is 1 domain to scan    if scan_domain =""  set all status =1                
                    if scan_domain:
                        scan_domain = scan_domain[0]
                except Exception as er:
                    log.error(er)
        
            else:
                log.warn("no  domain  to scan")  # test
                #sys.exit()
                time.sleep(600) #  set status  0


    def insert_sub(self,domain):
        data_cs = csv.reader(open("output/{name}/{name}.csv".format(name = domain)))
        insert_data =  []
        for line in data_cs:
            ain = line[0]
            ip = line[2]
            if ain != "domain":
                ips = ip.replace('[','').replace(']','').replace("'",'').replace('"','').split(",")
                if self.is_Intranet(ips[0]) == False:
                    insert_data.append((ain,'Null',domain,'Null',str(ips),'0','0','0'))
                else:
                    insert_data.append((ain,'Null',domain,'Null',str(ips),'0','0','1'))
        try:
            res = sql.insert_subdomain(insert_data)
            log.info(res)
            if res == "success":
                log.info("save {} success".format(domain))
                sendwx.send_data(" save {} success".format(domain))
            else:
                log.error(res)
                sendwx.send_data(" save {} error".format(domain))
                sendwx.send_data(str(res))
        except Exception as ess:
            log.error(ess)

    def ip_into_int(self,ip):
        return reduce(lambda x,y:(x<<8)+y,map(int,ip.split('.')))

    def is_Intranet(self,ip):    # 判断内网ip
        if str(ip).startswith("127.0.0") or str(ip) == "0.0.0.1":
            return True
        ip = self.ip_into_int(ip)
        net_a = self.ip_into_int('10.255.255.255') >> 24
        net_b = self.ip_into_int('172.31.255.255') >> 20
        net_c = self.ip_into_int('192.168.255.255') >> 16
        return ip >> 24 == net_a or ip >>20 == net_b or ip >> 16 == net_c

    def ini(self,domain):
        ip = self.get_ip("dasdsaqwewq."+domain)
        if ip:
            try:
                if ip not in self.black_ip.keys():
                    self.black_ip[ip] = self.blacktime
                    sql.insert_black(ip)
            except:
                self.black_ip[ip[0]] = self.blacktime

    def check_domain(self,ip):
        if ip in self.black_ip.keys():
            if self.black_ip[ip] < self.blacktime:
                self.black_ip[ip] += 1
                return True
            elif self.black_ip[ip] == self.blacktime:
                self.black_ip[ip] += 1
                sql.insert_black(ip)
                return False
            else:
                return False
        elif ip not in self.black_ip.keys():
            self.black_ip[ip] = 0
            return True

    def get_ip(self,domain):
        res = []
        try:
            record = self.resolver.query(domain)
            for A_CNAME in record.response.answer:
                for item in A_CNAME.items:
                    if item.rdtype == dns.rdatatype.from_text('A'):
                        res.append(str(item))
                    elif (item.rdtype == dns.rdatatype.from_text('CNAME')):
                        # res.append(str(item))
                        pass
                    elif (item.rdtype == dns.rdatatype.from_text('TXT')):
                        pass
                    elif item.rdtype == dns.rdatatype.from_text('MX'):
                        pass
                    elif item.rdtype == dns.rdatatype.from_text('NS'):
                        pass
        except:
            return False
        if res :
            return res
        else :
            return False

    def write_ams_sub(self,scan_domain,filename,amass_json,other_file):
        insdomain = scan_domain
        if os.path.exists(filename):
            with open(filename) as f:
                subfind_list = []
                for domain in f.readlines():
                    domain = domain.replace('\n','').replace("..",".") 
                    if not self.check_black(domain):
                        subfind_list.append(domain)
                subfind_list = list(set(subfind_list))
                log.info("subfinder Total  find "+str(len(subfind_list))+" domains")
        else:
            subfind_list = []
        f.close()


        with open(amass_json,'r') as amsjson:
            ams_list = []
            for i in amsjson.readlines():
                i = json.loads(i)
                if i['name']:
                    if i['name'].endswith(scan_domain) and not self.check_black(i['name']) :
                        ams_list.append(i['name'].replace("..",".").replace("\n",""))
            ams_list = list(set(ams_list))
            log.info("amass Total  find "+str(len(ams_list))+" domains")
        amsjson.close()
        all_list = list(set(ams_list+subfind_list))
        with open(other_file,'w') as aldomain:
            insert_data =  []
            for i in all_list: #  alllog  不做处理  待定
                ips = self.get_ip(i)  
                if ips:  
                    if False not in map(self.check_domain,[ip for ip in ips]):
                        aldomain.write(i+","+str(ips)+'\n')
                        # log.info(ips)
                        if self.is_Intranet(ips[0]) == False:
                            insert_data.append((i,'Null',insdomain,'Null',str(ips),'0','0','0'))
                        else:
                            insert_data.append((i,'Null',insdomain,'Null',str(ips),'0','0','1'))
            log.info(insert_data)
            res = sql.insert_subdomain(insert_data)
            log.info(res)    
        aldomain.close()
        real_dict = set()
        for dic in all_list:
            dic = dic.strip(scan_domain).split(".")
            for name in dic:
                real_dict.add(name)
        log.info(len(real_dict))
        with open(self.config_main.real_subdict,"r") as f:
            for i in f.readlines():
                real_dict.add(i.replace("\n",""))
        f.close()
        with open(self.config_main.real_subdict,"w") as f:
            for dic in real_dict:
                f.write(dic+"\n")
        f.close()

        del subfind_list,all_list,ams_list,real_dict
        
    # def query_domain(self, domain):
        
    def check_black(self,domain):
        for bl in  self.config_main.black_list:
            if bl in domain:
                return True
        return False

if __name__ == "__main__":
    item = start()
    item.subscan()
