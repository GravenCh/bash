#! /bin/python3
import os
import sys
def check():
    try:
        import psutil
    except:
        os.system('apt install python3-psutil')
    try:
        import socket
    except:
        os.system('pip3 install socket')
    try:
        import re
    except:
        os.system('pip3 install re')
    try:
        import time
    except:
        os.system('pip3 install time')
    try:
        import json
    except:
        os.system('pip3 install json')
    try:
        import threading
    except:
        os.system('pip3 install threading')
    try:
        import requests
    except:
        os.system('pip3 install requests')
    try:
        import psutil,re,time,json,threading,requests,socket
    except:
        print("Please Install Python3 Pip first.")
        sys.exit()

check()
import threading
import json
import psutil
import re
import time
import requests
import socket


server_address=""
pwd=""
delay="-"
Pocketlossrate="- %"
status=0

def get_opt():
    try:
        global server_address,pwd
        for i in range(1,len(sys.argv)):
            if sys.argv[i].find("-a=",0,3)!=-1:
                server_address=sys.argv[i][3:len(sys.argv[i])]
            elif sys.argv[i].find("-p=",0,3)!=-1:
                pwd=sys.argv[i][3:len(sys.argv[i])]
    finally:
        if server_address == "" or pwd == "":
            print(sys.argv[0]+" -p=<password> -a=<sever_address>")
            print("Please note that there is no space between the equal sign and the parameter")
            sys.exit()
def calbyte(num):
    unit=['B','KB','MB','GB','TB','PB','EB','ZB','YB']
    cnt=0
    while num >= 1024:
        num/=1024
        cnt+=1
    return [round(num,2),unit[cnt]]
def str_cnt(str1,str2):
    pos=0
    cnt=-1
    while(pos != -1):
        pos=str1.find(str2,pos+1,len(str1))
        cnt+=1
    return cnt
def caltime(sys_time,boot_time):
    tmp=sys_time-boot_time
    day=int(tmp/60/60/24)
    tmp-=60*60*24*day
    hr=int(tmp/60/60)
    tmp-=60*60*hr
    min=int(tmp/60)
    sec=int(tmp)-60*min
    time_list=[day,hr,min,sec]
    if time_list[0]!=0:
        return str(time_list[0])+"天"+str(time_list[1])+"时"
    elif time_list[1]!=0:
        return str(time_list[1])+"时"+str(time_list[2])+"分"
    elif time_list[2]!=0:
        return str(time_list[2])+"分"+str(time_list[3])+"秒"
    else:
        return str(time_list[3])+"秒" 

def get_network_ip(ipv4,ipv6):
    try:
        tmp=os.popen("ifconfig | grep inet6 | awk '{print $2}'").read()
        for line in tmp.splitlines():
            if line.find("fe",0,2)==-1 and line!="::1":
                ipv6.append(line)
    finally:
        if len(ipv6)==0:
            ipv6.append("error")
    try:
        tmp=os.popen("ifconfig | grep inet | awk '{print $2}'").read()
        for line in tmp.splitlines():
            if line not in ipv6 and line.find("fe",0,2)==-1 and line!="::1" and line!="127.0.0.1":
                ipv4.append(line)
    finally:
        if len(ipv4)==0:
            ipv4.append("error")
    return  0
def get_tcp_connection(tcp,tcp_stat):
    tmp=os.popen('netstat -nat').read()
    for i in range (0,len(tcp_stat)):
        tcp.append(str_cnt(tmp,tcp_stat[i]))
def get_udp_connection():
    tmp=os.popen('netstat -nau').read()
    udp=str_cnt(tmp,"udp")
    return udp
def get_disk_usage():
    disk_total=0
    disk_used=0
    devs = psutil.disk_partitions()
    for dev in devs:
        disk_total+=psutil.disk_usage('%s'%dev.mountpoint)[0]
        disk_used+=psutil.disk_usage('%s'%dev.mountpoint)[1]
    try:
        disk_percent=round(disk_used/disk_total*100,2)
    except:
        disk_percent="error"
    return [str(calbyte(disk_total)[0])+calbyte(disk_total)[1],str(calbyte(disk_used)[0])+calbyte(disk_used)[1],str(disk_percent)]
def get_delay():
    global delay,Pocketlossrate
    while True:
        if status==1:
            return
        tmp=os.popen("ping 223.5.5.5 -c 50 -i 0.2 -w 10").read()
        delay_flag=re.compile(r'.*/(.*)/.*/.*')
        Pocketlossrate_flag=re.compile(r' ([0-9]*\.*[0-9]*)% ')
        try:
            delay=str(int(float(re.search(delay_flag,tmp).group(1))))        
        except:
            delay="error"
        try:
            Pocketlossrate=str(int(float(re.search(Pocketlossrate_flag,tmp).group(1))))+" %"
        except:
            Pocketlossrate="error"
def get_cpuinfo():
    total_tmp=0
    for i in range(0,3):
        total_tmp+=psutil.cpu_percent(interval=0.1,percpu=False)
    cpu_percent=round(total_tmp/3,2)
    cpu_cnt=psutil.cpu_count(logical=True)
    cpu_logical_percent_list1=psutil.cpu_percent(interval=0.1,percpu=True)
    cpu_logical_percent_list2=psutil.cpu_percent(interval=0.1,percpu=True)
    cpu_logical_percent_list3=psutil.cpu_percent(interval=0.1,percpu=True)
    cpu_logical_percent_list=[]
    for i in range(0,cpu_cnt):
        cpu_logical_percent_list.append(round((cpu_logical_percent_list1[i]+cpu_logical_percent_list2[i]+cpu_logical_percent_list3[i])/3,2))
    return [cpu_percent,cpu_logical_percent_list]



def get_netflow():
    tmp=os.popen("ifconfig |grep 'TX packets'|awk '{print $5}'").read()
    flag=re.compile(r'.*')
    TX_list=flag.findall(tmp)
    tmp=os.popen("ifconfig |grep 'RX packets'|awk '{print $5}'").read()
    flag=re.compile(r'.*')
    RX_list=flag.findall(tmp)
    try:
        TX=0
        for num in TX_list:
            if num!='':
                TX+=int(num)
    except:
        TX="error"
    try:
        RX=0
        for num in RX_list:
            if num!='':
                RX+=int(num)
    except:
        RX="error"
    return [TX,RX]



def func():
    data={}
    hostname=socket.gethostname()
    data['hostname']=hostname
    boot_time=psutil.boot_time()
    sys_time=time.time()
    run_time=caltime(sys_time,boot_time)
    data['run_time']=run_time
    data['sys_time']=sys_time
    cpu_info=get_cpuinfo()
    data['cpu_percent']=cpu_info[0]
    data['cpu_logical_percent_list']=cpu_info[1]
    vir_memory_list=psutil.virtual_memory()
    vir_total=vir_memory_list[0]
    vir_used=vir_memory_list[0]-vir_memory_list[1]
    data['memory_total']=str(calbyte(vir_total)[0])+calbyte(vir_total)[1]
    data['memory_used']=str(calbyte(vir_used)[0])+calbyte(vir_used)[1]
    try:
        data['memory_percent']=str(round(vir_used/vir_total*100,2))
    except:
        data['memory_percent']="error"
    swap_memory_list=psutil.swap_memory()
    swap_total=swap_memory_list[0]
    swap_used=swap_memory_list[1]
    data['swap_total']=str(calbyte(swap_total)[0])+calbyte(swap_total)[1]
    data['swap_used']=str(calbyte(swap_used)[0])+calbyte(swap_used)[1]
    try:
        data['swap_percent']=str(round(swap_used/swap_total*100,2))
    except:
        data['swap_percent']="error"
    disk_usage_list=get_disk_usage()
    disk_total=disk_usage_list[0]
    disk_used=disk_usage_list[1]
    disk_percent=disk_usage_list[2]
    data['disk_total']=disk_total
    data['disk_used']=disk_used
    data['disk_percent']=disk_percent
    ipv4=[]
    ipv6=[]
    get_network_ip(ipv4,ipv6)
    ipv4.sort()
    ipv6.sort()
    data['ipv4']=ipv4
    data['ipv6']=ipv6
    tcp=[]
    tcp_stat=["tcp","LISTEN","SYN_SENT","SYN_RECEIVED","ESTABLISHED","FIN_WAIT_1","CLOSE_WAIT","CLOSING","LAST_ACK","TIME_WAIT","CLOSED"]
    get_tcp_connection(tcp,tcp_stat)
    data['tcp_total']=str(tcp[0])
    tcp_dict={}
    for i in range(1,len(tcp)):
        tcp_dict[tcp_stat[i]]=tcp[i]
    data['tcp_stat']=tcp_dict
    udp=get_udp_connection()
    data['udp_total']=str(udp)    
    net_pre_list=get_netflow()
    time.sleep(0.4)
    net_list=get_netflow()
    net_pre_sent=net_pre_list[0]
    net_pre_recv=net_pre_list[1]
    net_sent=net_list[0]
    net_recv=net_list[1]
    try:
        net_sent_speed=(net_sent-net_pre_sent)/0.4
        net_recv_speed=(net_recv-net_pre_recv)/0.4
        data['net_sent_speed']=str(calbyte(net_sent_speed)[0])+calbyte(net_sent_speed)[1]+"/s"
        data['net_recv_speed']=str(calbyte(net_recv_speed)[0])+calbyte(net_recv_speed)[1]+"/s"
    except:
        data['net_sent_speed']="error"
        data['net_recv_speed']="error"
    if net_sent!="error":
        data['net_sent']=str(calbyte(net_sent)[0])+calbyte(net_sent)[1]
    else:
        data['net_sent']==net_sent
    if net_recv!="error":
        data['net_recv']=str(calbyte(net_recv)[0])+calbyte(net_recv)[1]
    else:
        data['net_recv']=net_recv
    data['delay']=delay 
    data['Pocketlossrate']=Pocketlossrate    
    return data


if __name__=="__main__": 
    get_opt()
    threading.Thread(target=get_delay).start()
    while True:
        if status==1:
            sys.exit()
        try:
            src_data=func()
            src_data['password']=pwd
            data=json.dumps(src_data)
            if not data:
                continue
            res=requests.post(server_address, data=data)
            print ('server reply:', res.text)
        except KeyboardInterrupt:
            print("Caught Exception: KeyboardInterrupt")
            sys.exit()
        except Exception as e:
            print("Caught Exception:", e)
