#  Environment: python 3.8.10 or 3.6.8, python2 can't use this file
#  Author:     jiang
#  CreateTime: 2024/7/3
#  UpdateTime: 2024/7/4

# This is released version

import subprocess
import re
import sys
import redis
import time

def get_osd_addr():   
    osd_addr_dic = {}
    OSD_DUMP = subprocess.Popen(['ceph osd dump --format=json'], stdout = subprocess.PIPE, shell = True)
    OSD_DUMP = OSD_DUMP.stdout.read()
    OSD_DUMP = OSD_DUMP.decode('utf-8')
    #print('OSD_DUMP =', OSD_DUMP)
    OSD_DUMP = eval(OSD_DUMP, {"true":True, "false":False})  #{"true":True,"false":False,"null":None}
    print('OSD_DUMP =', OSD_DUMP)
    
    for osd_num in range(len(OSD_DUMP['osds'])):
        if ((OSD_DUMP['osds'][osd_num]['up']) and (OSD_DUMP['osds'][osd_num]['in'])) == 1:
            osd_addr = OSD_DUMP['osds'][osd_num]['cluster_addr']
            osd_addr = re.findall(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])', osd_addr)[0] #re.findall返回string中所有与pattern相匹配的全部字串，返回形式为数组
            osd_addr_dic[osd_num] = osd_addr   #osd_num = OSD_DUMP['osds'][osd_num]['osd']
            print ("osd_addr_dic[%s] = %s insert completed." % (osd_num, osd_addr))
    #print (osd_addr_dic)
        
    return osd_addr_dic

def get_osd_range(optimize_range):
    print("***get_osd_range(%s)***" % optimize_range)

    osd_range = []
    pgs_per_osd = {}
    
    OSD_RANGE = subprocess.Popen(['ceph osd df tree --format=json'], stdout = subprocess.PIPE, shell = True)

    OSD_RANGE = OSD_RANGE.stdout.read()
    OSD_RANGE = OSD_RANGE.decode('utf-8')
    OSD_RANGE = eval(OSD_RANGE)
    print('OSD_RANGE =', OSD_RANGE)

    for i in range(len(OSD_RANGE['nodes'])):
        if OSD_RANGE['nodes'][i]['name'][:len(optimize_range)] == optimize_range and OSD_RANGE['nodes'][i]['children'][0] > 0:
            for host_child in OSD_RANGE['nodes'][i]['children']:
                osd_range.append(host_child)
                print("find OSD_host is %s, osd_range.append(%s) completed." % (OSD_RANGE['nodes'][i]['name'], host_child))
            continue
        if OSD_RANGE['nodes'][i]['id'] in osd_range: 
            pgs_per_osd[OSD_RANGE['nodes'][i]['id']] = OSD_RANGE['nodes'][i]['pgs']
            print("find OSD_ID = %s, which pgs = %s, pgs_per_osd[%s] = %s insert completed." % (OSD_RANGE['nodes'][i]['id'], OSD_RANGE['nodes'][i]['pgs'], OSD_RANGE['nodes'][i]['id'], OSD_RANGE['nodes'][i]['pgs']))
        
    print('osd_range =', osd_range)
    print('pgs_per_osd =', pgs_per_osd)
    
    print("***get_osd_range(%s)*** done" % optimize_range)
    return osd_range, pgs_per_osd

def get_osd_info_dic(osd_addr_dic, dict, times, optimize_range, osd_range, pgs_per_osd):
    print('***get_osd_info_dic()***')
    pool = redis.ConnectionPool(host='127.0.0.1', port=6379, db=0)

    #TODO get_osd_info_dic
    
    print('***get_osd_info_dic() done***')

#optimize_range: ceph-node1、ceph-node2……
def get_optimize_range():
    print("Please select optimize_range!\n"
          "Enter ceph-node: optimize_range is root of ceph-nodeX;\n")
    optimize_range = str(input('please input optimize_range:'))
    return optimize_range

def get_optimize_mode():
    print("Please select input optimize_mode!\n"
          "Enter 0: optimize_mode is heterogeneous_optimize_read or optimize_read;\n"
          "Enter 1: optimize_mode is heterogeneous_optimize_write or optimize_write;\n")
    optimize_mode = int(input('please input optimize_mode:'))
    return optimize_mode

def get_HP_flag():
    print("Please select whether to use the HP algorithm!\n"
          "Enter 0: no;\n"
          "Enter 1: yes;\n")
    HP_flag = bool(input('please input HP_flag:'))
    return HP_flag

def get_HW_flag():
    print("Please select whether to use the HW algorithm!\n"
          "Enter 0: no;\n"
          "Enter 1: yes;\n")
    HW_flag = bool(input('please input HW_flag:'))
    return HW_flag

def main():
    #get_osd_addr()
    #get_osd_range('ssd_host&hdd_host')
    
    #optimize_mode = get_optimize_mode()
    #optimize_range = get_optimize_range()
    
    #HP_flag = get_HP_flag()
    #HW_flag = get_HW_flag()
    
    optimize_mode = 1
    optimize_range = 'ceph-node'
    HP_flag = 1
    HW_flag = 1

    while True:
        print("optimize_mode = %s, optimize_range = %s, HP_flag = %s, HW_flag = %s" 
              % (optimize_mode, optimize_range, HP_flag, HW_flag))
        
        osd_info = {}
        osd_addr_dic = get_osd_addr()   #osd_addr_dic = {2: '192.168.207.183', 3: '192.168.207.182', 5: '192.168.207.182', 7: '192.168.207.181'}
        print("osd_addr_dic = %s" % osd_addr_dic)
        optimize_osd_range, pgs_per_osd = get_osd_range(optimize_range)
        print("osd_range = %s, pgs_per_osd = %s" % (optimize_osd_range, pgs_per_osd))
    

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Incorrect parameter input, input argv len = %s" % len(sys.argv))
        sys.exit(0)
    
    #key = ceph_id, value = ip
    ceph_to_ip = {'1': '192.168.206.181', 
                  '2': '192.168.206.182', 
                  '3': '192.168.206.183', 
                  '4': '192.168.206.184',  }
    

    if __name__ == '__main__':
        main()