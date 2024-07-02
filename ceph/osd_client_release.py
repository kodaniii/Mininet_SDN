#  Environment: python 3.8.10 or 3.6.8, python2 can't use this file
#  Author:     jiang
#  CreateTime: 2024/6/30
#  UpdateTime: 2024/7/2

# This is released version

#coding=UTF-8

import time
from socket import *
from scapy.all import *
import subprocess
import re
import sys
import psutil
import json

delay_all = []

def _get_delay(ip):
    print('***_get_delay()***')

    delay_time_sum = 0
    delay_all.clear()
    for _ in range(15):
        p = subprocess.Popen(['ping -c 1 '+ ip], stdout = subprocess.PIPE, shell = True)
        
        #for _line in p.stdout.readlines():
        #    print(_line.decode('utf-8'))
        p_msg = p.stdout.read()
        p_msg = p_msg.decode('utf-8')
        #print("ip=%s, p_msg=%s" % (ip, p_msg))
        
        p_msg_delay_time = re.search((u'time=\d+\.+\d*'), p_msg)
        #print(p_msg_delay_time[0])
        if p_msg_delay_time is not None:
            delay_time = filter(lambda x: x in '1234567890.', p_msg_delay_time[0])
            #print("p_msg_delay_time=%s" % delay_time)
            
            #filter -> float
            delay_time_list = list(delay_time)
            delay_time_str = "".join(delay_time_list)
            delay_time = float(delay_time_str)
            
            delay_time = max(delay_time, 0)
            delay_all.append(delay_time)
            #print("delay_all(%s times) = %s insert completed." % (_time, delay_time))
            delay_time_sum += delay_time
            #print("delay_time_sum += %s ms (+ delay_time[%s]: %s ms)" % (delay_time_sum, _time, delay_time))
    delay_time = round(float(delay_time_sum) / 15, 2)
    print('delay_time =', delay_time)
    #print('delay_time[] len =', len(delay_all))

    print('***_get_delay() done***')
    return delay_time

def _get_packet_loss(ip):
    print('***_get_packet_loss()***')
    p = subprocess.Popen(['ping -c 20 '+ ip], stdout = subprocess.PIPE, shell = True)

    #p_msg = p.stdout.readlines()
    #p_msg = p_msg
    #for _line in p_msg:
    #    print('*:', _line.decode('utf-8'))
    p_msg = p.stdout.read()
    p_msg = p_msg.decode('utf-8')
    #print('p_msg =', p_msg)
    p_msg_packet_loss = re.search(r'\d+%', p_msg)

    if p_msg_packet_loss is not None:
        packet_loss = p_msg_packet_loss[0]
        #print(packet_loss)
        #print('****')
        packet_loss = packet_loss.split('%')[0]
        packet_loss = int(packet_loss)
        print('packet_loss =', packet_loss)

    print('***_get_packet_loss() done***')
    return packet_loss * 100

def _get_delay_jitter_old():
    print('***_get_delay_jitter_old()***')
    delay_diff_sum = 0
    for each in range(-1, -16, -1):
        #print("each =", each)
        if each >= -14:
            delay_diff = abs(float(delay_all[each]) - float(delay_all[each-1])) 
            delay_diff_sum += delay_diff
            #print("delay_dif = %s (+ delay_diff %s)" % (delay_diff_sum, delay_diff))
    delay_jitter = round(delay_diff_sum/14, 2)
    print(delay_jitter)

    print('***_get_delay_jitter_old() done***')         
    return delay_jitter

def _get_delay_jitter(avg_delay):
    print('***_get_delay_jitter()***')
    variance = sum([((float(_delay) - avg_delay) ** 2) for _delay in delay_all]) / (len(delay_all) - 1)
    #print("variance = %s" % variance)
    delay_jitter = round(variance * 10, 3)
    print(delay_jitter)

    print('***_get_delay_jitter() done***')
    return delay_jitter

def _get_cpu():
    print('***_get_cpu()***')
    cpu_use = min(psutil.cpu_percent(interval=1, percpu=False), 100)
    print(cpu_use)
    print('***_get_cpu() done***')
    return round(cpu_use, 2)

def _get_mem():
    print('***_get_mem()***')
    mem_use = min(psutil.virtual_memory().percent, 100)
    print(mem_use)
    print('***_get_mem() done***')
    return round(mem_use, 2)

def _get_io():
    print('***_get_io()***')
    devices = {}
    osd_io = {}

    osd_disk_json = subprocess.getoutput('ceph-volume lvm list --format=json')
    osd_disk = json.loads(osd_disk_json)
    osd_disk = json.dumps(osd_disk)
    osd_disk = eval(osd_disk)
    #print('osd_disk =', osd_disk)

    # use regular expression matches the ceph disk and record
    partitions = psutil.disk_partitions(all=True)
    #print(partitions)

    pattern = re.compile(r'/var/lib/ceph/osd/')
    # find device and it's index in partitions
    for p in partitions:
        #print('partition =', p)
        if pattern.match(p.mountpoint):
            #print('p.mountpoint =', p.mountpoint)
            devices_name = p.mountpoint[23:]
            #print('devices_name =', devices_name)
            devices[devices_name] = osd_disk[str(devices_name)][0]['devices'][0][5:]
    #print('devices =', devices) #{'7': 'sdc', '1': 'sdb'}

    # osd_io --> result:{0: 0.0, 39: 0.0, 10: 0.0, 49: 0.0, 23: 0.0, 59: 0.0}
    for key in devices:
        osd_num = int(key)
        osd_io.setdefault(osd_num,{'r':0,'w':0})
        pre_read_bytes = psutil.disk_io_counters(perdisk=True)[devices[key]].read_bytes
        pre_write_bytes = psutil.disk_io_counters(perdisk=True)[devices[key]].write_bytes
        time.sleep(1)
        after_read_bytes = psutil.disk_io_counters(perdisk=True)[devices[key]].read_bytes
        after_write_bytes = psutil.disk_io_counters(perdisk=True)[devices[key]].write_bytes
        read_bytes = float(after_read_bytes - pre_read_bytes)/1024
        write_bytes = float(after_write_bytes - pre_write_bytes)/1024
        osd_io[osd_num]['r'] = read_bytes
        osd_io[osd_num]['w'] = write_bytes
        total_kbytes = float(read_bytes + write_bytes)/1024
        total_kbytes = round(total_kbytes, 2)
        osd_io[osd_num] = total_kbytes  #write + read kB/s
    print('osd_io[%s] = %s KB/s' % (osd_num, osd_io))
    print('***_get_io() done***')
    return osd_io

# send data
# give a host which in the network but no host bound it (IP, PORT) to trigger table-miss
def _send_data(ip):
    while True:
        try:
            avg_delay = _get_delay(ip)
            packet_loss = _get_packet_loss(ip)
            #delay_jitter_old = _get_delay_jitter_old()
            delay_jitter = _get_delay_jitter(avg_delay)
            cpu = _get_cpu()
            mem = _get_mem()
            io = _get_io()
            #data = str((avg_delay, cpu, mem, io))
            #data = str((avg_delay, packet_loss, delay_jitter_old, delay_jitter))
            data = str((avg_delay, packet_loss, delay_jitter, cpu, mem, io))
            if not data:
                print('not data, break')
                break
            #send(IP(src='172.25.7.191',dst='172.25.7.223')/ARP())
            print('send data msg =', data)
            #send(IP(src='192.168.206.181', dst='10.0.0.233')/UDP(dport=23333)/Raw(load=data))  #physical environment
            
            #save data to local file
            with open('save_update_data', 'w') as file:
                file.write(data)
            
            time.sleep(1)
        except Exception as e:
            print('Error: ', e)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Incorrect parameter input, input argv len = %s" % len(sys.argv))
    
    #key = ceph_id, value = ip
    ceph_to_ip = {'1': '192.168.206.181', 
                  '2': '192.168.206.182', 
                  '3': '192.168.206.183', 
                  '4': '192.168.206.184',  }
    ip = ceph_to_ip[sys.argv[1]]
    
    _send_data(ip)
