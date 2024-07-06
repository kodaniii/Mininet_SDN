# The host in Mininet reads information from external storage server hosts and forwards the information to the corresponding ryu controller.
#  Author:     jiang
#  CreateTime: 2024/7/2
#  UpdateTime: 2024/7/6

import subprocess
import sys
from socket import *
from scapy.all import *
import time

def _get_msg(ip):
    #get (0.04, 0, 0.001, 1.0, 77.3, {5: {'r': 0.0, 'w': 0.0}, 3: {'r': 0.0, 'w': 0.0}}, '192.168.206.182')
    p = subprocess.Popen(['ssh ' + ip + ' cat save_update_data'], stdout = subprocess.PIPE, shell = True)
    p_msg = p.stdout.readline()
    p_msg = p_msg.decode('utf-8')
    if p_msg is not None:
        print("get storage_server_ip(%s) p_msg= %s" % (ip, p_msg))
    else:
        print('ERROR: p_msg is None')
    
    """
    p_msg = eval(p_msg)
    print('eval(p_msg) =', p_msg)

    ip_to_virtual_ip = {
        "192.168.206.181": "10.0.0.1",
        "192.168.206.182": "10.0.0.2",
        "192.168.206.183": "10.0.0.3",
        "192.168.206.184": "10.0.0.4",
    }
    virtual_ip = ip_to_virtual_ip[ip]
    print("virtual_ip = %s" % virtual_ip)
    
    ryu_controller_ip = '192.168.206.179'

    #get {'10.0.0.2': 10000.0, '10.0.0.1': 10000.0, '10.0.0.3': 10000.0, '10.0.0.5': 10000.0}
    p = subprocess.Popen(['ssh ' + ryu_controller_ip + ' cat save_bw_info'], stdout = subprocess.PIPE, shell = True)
    bw_msg = p.stdout.readline()
    bw_msg = bw_msg.decode('utf-8')
    if bw_msg is not None:
        print("get bw_msg =", bw_msg)
    else:
        print('ERROR: bw_msg is None')
        
    bw_msg = eval(bw_msg)
    print('eval(bw_msg) =', bw_msg)

    free_bw = bw_msg[virtual_ip]
    print("get free_bw = %s" % free_bw)


    delay, packet_loss, delay_jitter, cpu, mem, io, _ip_address = p_msg
    p_msg = str((free_bw, delay, packet_loss, delay_jitter, cpu, mem, io, _ip_address))
    print("p_msg = %s" % p_msg)

    """
    return p_msg

def _send_data(ip, data):
    try:
        send(IP(src=ip, dst='10.0.0.233')/UDP(dport=23333)/Raw(load=data))
        print("send data = %s success." % data)
    except Exception as e:
        print('Error: ', e)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Incorrect parameter input, input argv len = %s" % len(sys.argv))
        sys.exit(0)
    
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
        