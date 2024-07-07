#  Environment: python 3.8.10 or 3.6.8, python2 can't use this file
#  Author:     jiang
#  CreateTime: 2024/7/3
#  UpdateTime: 2024/7/7

# This is released version

import subprocess
import re
import sys
import redis
import time

#key = osd_id, value = ip_address 
def get_osd_id_to_ip_addr():   
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
            osd_addr = re.findall(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])', osd_addr)[0]
            osd_addr_dic[osd_num] = osd_addr   #osd_num = OSD_DUMP['osds'][osd_num]['osd']
            print ("osd_addr_dic[%s] = %s insert completed." % (osd_num, osd_addr))
    #print(osd_addr_dic)
        
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

# get osd and its' bandwidth for <length> times
#parameter[:6] = {0: '192.168.206.184', 1: '192.168.206.181', 2: '192.168.206.183', 3: '192.168.206.182', 4: '192.168.206.184', 5: '192.168.206.182', 6: '192.168.206.183', 7: '192.168.206.181'}, 
#             {}, 5, ceph-node, [7, 1, 5, 3, 6, 2, 4, 0], {1: 80, 7: 104, 3: 109, 5: 99, 2: 96, 6: 88, 0: 103, 4: 89}
def get_osd_info_dic(osd_to_ip, osd_info, times, optimize_range, need_optimize_osd_range, pgs_per_osd, redis_ip_list, redis_ip_value):
    print('***get_osd_info_dic()***')
    
    print("parameter = %s, %s, %s, %s, %s, %s"
          % (osd_to_ip, osd_info, times, optimize_range, need_optimize_osd_range, pgs_per_osd))
    pool = redis.ConnectionPool(host='127.0.0.1', port=6379, db=0)
    r = redis.Redis(connection_pool=pool)
    
    #delete key in osd_bw but not in osd_to_ip
    # in order that host is down in runtime
    #{}, key = osd_id
    print("osd_info =", osd_info)
    if osd_info:
        for osd_id in osd_info.keys():
            if osd_id not in osd_to_ip:
                print("osd_id = %s, osd_to_ip = %s" % (osd_id, osd_to_ip))
                del osd_info[osd_id]
            for x in osd_info[osd_id].keys():
                #print("len(osd_info[%s][%s]) = %s" % (osd_id, x, len(osd_info[osd_id][x])))
                if len(osd_info[osd_id][x]) == times:
                    osd_info[osd_id][x].pop(0)

    redis_ip_list = []  #need modify this
    #update osd_bw of the osd in osd_to_ip
    for osd_id in osd_to_ip.keys():
        redis_ip = osd_to_ip[osd_id]
    
        if redis_ip is None or redis_ip in redis_ip_list:
            continue
        
        redis_ip_list.append(redis_ip)
        
        redis_value = r.get(str(redis_ip))
        redis_value = redis_value.decode('utf-8')

        print("redis_value = %s" % redis_value)
        print("redis_ip_value[%s] = %s" % (redis_ip, redis_ip_value[redis_ip]))
        
        while redis_value == redis_ip_value[redis_ip]:
            redis_value = r.get(str(redis_ip))
            redis_value = redis_value.decode('utf-8')
            print("FROM Redis: ip = %s, value = %s" % (redis_ip, redis_value))

            if redis_value is None:
                continue
            
            print("redis_value == redis_ip_value[%s] is %s, wait..." % (redis_ip, redis_value))
            time.sleep(2)
        redis_ip_value[redis_ip] = redis_value
        #print("redis_value = %s" % redis_value)
        #print("redis_ip_value[%s] = %s" % (redis_ip, redis_ip_value[redis_ip]))

        if osd_id not in need_optimize_osd_range:
            continue

        # osd_info.setdefault(osd_id, {'bw': [], 'delay': [], 'cpu': [], 'mem': [], 'pgs':[], 'r': [], 'w':[]})
        #osd_info.setdefault(osd_id, {'bw': [], 'cpu': [], 'mem': [], 'pgs':[], 'r': [], 'w':[]})
        osd_info.setdefault(osd_id, {'bw': [], 'avg_delay': [], 'packet_loss': [], 'delay_jitter': [], 
                                     'cpu': [], 'mem': [], 'pgs':[], 'r': [], 'w':[]})
        osd_info_dic = eval(redis_value)
        print('osd_info_dic =', osd_info_dic)
        #osd_info_dic = (9999.97, 0.06, 0, 0.034, 8.2, 93.6, {7: {'r': 0.0, 'w': 0.0}, 1: {'r': 0.0, 'w': 0.0}})
        bw = osd_info_dic[0]
        # delay = osd_info_dic['delay']
        avg_delay = osd_info_dic[1]
        packet_loss = osd_info_dic[2]
        delay_jitter = osd_info_dic[3]
        cpu = osd_info_dic[4]
        mem = osd_info_dic[5]
        pgs = pgs_per_osd[osd_id]
        r_io = osd_info_dic[6][osd_id]['r']
        w_io = osd_info_dic[6][osd_id]['w']

        print("osd_id %s: bw = %s, avg_delay = %s, packet_loss = %s, delay_jitter = %s, "\
              "cpu = %s, mem = %s, pgs = %s, r_io = %s, w_io = %s" \
                % (osd_id, bw, avg_delay, packet_loss, delay_jitter, cpu, mem, pgs, r_io, w_io))

        osd_info[osd_id]['bw'].append(bw)
        # osd_info[osd_id]['delay'].append(delay)
        osd_info[osd_id]['avg_delay'].append(avg_delay)
        osd_info[osd_id]['packet_loss'].append(packet_loss)
        osd_info[osd_id]['delay_jitter'].append(delay_jitter)
        osd_info[osd_id]['cpu'].append(cpu)
        osd_info[osd_id]['mem'].append(mem)
        osd_info[osd_id]['pgs'].append(pgs)
        osd_info[osd_id]['r'].append(r_io)
        osd_info[osd_id]['w'].append(w_io)
        print("osd_info[%s] = %s" % (osd_id, osd_info[osd_id]))
    #print('get_osd_info_dict....end\n')
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
    #get_osd_id_to_ip_addr()
    #get_osd_range('ssd_host&hdd_host')
    
    #optimize_mode = get_optimize_mode()
    #optimize_range = get_optimize_range()
    
    #HP_flag = get_HP_flag()
    #HW_flag = get_HW_flag()
    
    optimize_mode = 1
    optimize_range = 'ceph-node'
    HP_flag = 1
    HW_flag = 1
    
    times = 5

    ip_convert = {
        '192.168.207.181': '192.168.206.181',
        '192.168.207.182': '192.168.206.182',
        '192.168.207.183': '192.168.206.183',
        '192.168.207.184': '192.168.206.184',
    }

    print("optimize_mode = %s, optimize_range = %s, HP_flag = %s, HW_flag = %s" 
            % (optimize_mode, optimize_range, HP_flag, HW_flag))
    
    osd_info = {}
    osd_to_ip = get_osd_id_to_ip_addr()   
    #osd_to_ip = {0: '192.168.207.184', 1: '192.168.207.181', 2: '192.168.207.183', 3: '192.168.207.182', 
                 #4: '192.168.207.184', 5: '192.168.207.182', 6: '192.168.207.183', 7: '192.168.207.181'}

    for _key, _value in osd_to_ip.items():
        osd_to_ip[_key] = ip_convert[osd_to_ip[_key]]

    print("osd_to_ip = %s" % osd_to_ip)
    optimize_osd_range, pgs_per_osd = get_osd_range(optimize_range)
    print("optimize_osd_range = %s, pgs_per_osd = %s" % (optimize_osd_range, pgs_per_osd))
    
    redis_ip_list = []
    redis_ip_value = {} #duplicate results filter

    for _key, _value in osd_to_ip.items():
        redis_ip_value.setdefault(_value, None)

    while True:

        # evertime update's interval is 60s
        for i in range(times):
            get_osd_info_dic(osd_to_ip, osd_info, times, optimize_range, optimize_osd_range, pgs_per_osd, redis_ip_list, redis_ip_value)
            print("----------------osd info is----------------")
            for key in osd_info.keys():
                print('osd_%s: %s' % (key, osd_info[key]))
            time.sleep(7)
    
    
if __name__ == '__main__':
        main()