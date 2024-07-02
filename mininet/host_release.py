# The host in Mininet reads information from external storage server hosts and forwards the information to the corresponding ryu controller.
#  Author:     jiang
#  CreateTime: 2024/7/2
#  UpdateTime: 2024/7/2

import subprocess
import sys
from socket import *
from scapy.all import *
import time

def _get_msg(ip):
    p = subprocess.Popen(['ssh ' + ip + ' cat save_update_data'], stdout = subprocess.PIPE, shell = True)
    p_msg = p.stdout.readline()
    p_msg = p_msg.decode('utf-8')
    if p_msg is not None:
        print("get storage_server_ip(%s) p_msg= %s" % (ip, p_msg))
    else:
        print('ERROR: p_msg is None')
    return p_msg

def _send_data(ip, data):
    try:
        send(IP(src=ip, dst='10.0.0.233')/UDP(dport=23333)/Raw(load=data))
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
    
    tmp_msg = ''
    while True:
        time.sleep(3)
        data = _get_msg(ip)
        if tmp_msg == data:
            continue
        else:
            tmp_msg = data
            _send_data(ip, data)
        