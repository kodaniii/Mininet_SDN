#  Environment: python 3.8.10 or 3.6.8, python2 can't use this file
#  Author:     jiang
#  CreateTime: 2024/7/5
#  UpdateTime: 2024/7/6

#coding=UTF-8

from scapy.all import *
import binascii
import redis
import time

while True:
    packet = ''
    data = ''
    length = 0
    src_ip = '192.168.206.179'
    dst_ip = '192.168.206.180'
    
    print("*")
    _filter = 'src host ' + src_ip + ' && dst host ' + dst_ip
    print('filter =', _filter)
    _iface = 'ens33'

    while length < 156:
        #packet = sniff(count = 1, iface = 'ens33', filter = 'Openflow') 
        #packet.summary()   #Ether / IP / TCP 192.168.206.179:6653 > 192.168.206.180:44166 PA / Raw

        packet = sniff(count = 1, iface = _iface, filter = _filter)
        packet.summary()
        # wrpcap("/root/shit.pcap", packet)
        try:
            length = len(packet[0].load)
            print("packet_msg = %s, length = %s" % (packet[0].load, len(packet[0].load)))
        except Exception as e:
            length = 0
    data = packet[0].load
    
    print("data =", data)
    
    #packet_msg = b"\x04\r\x00\xa0\xed\xe8\x85\xbe\xff\xff\xff\xff\x00\x00\x00\x01\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\xff\xff\xff\xfb\xff\xe5\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff6\xcd\x89\x95\xc0\xe7\x08\x00E\x00\x00j\x00\x01\x00\x00@\x11\xe0;\xc0\xa8\xce\xb5\n\x00\x00\xe9\x005[%\x00V\xd5I(0.03, 0, 0.0, 29.6, 94.3, {1: {'r': 0.0, 'w': 0.0}, 7: {'r': 0.0, 'w': 0.0}})", length = 160
    
    #packet_src_ip = packet[0][IP].src
    #print("src_ip = %s" % packet_src_ip)
    
    data_cut = b''
    count = 0
    for b in data:
        if count >= 82:
            data_cut += str(chr(b)).encode('utf-8')
            #print("count = %s, data_cut = %s" % (count, data_cut))
        else:
            count += 1
    print("Raw data = %s" % data_cut)
    print("Got Raw data success.")

    data = data_cut
    data = eval(data)
    print("eval(data) =", data)

    if not isinstance(data, tuple):
        #print(type(data))
        continue

    """
    #别看这里, 这里是packetout发包, 已经废弃噜
    #data = {
    #    '10.0.0.1': {'bw': 9999.98, 'delay': 0.04, 'cpu': 12.4, 'mem': 93.5, 'io': {1: {'r': 0.0, 'w': 0.0}, 7: {'r': 0.0, 'w': 0.0}}, 'delay_jitter': 0.002, 'packet_loss': 0}, 
    #    '10.0.0.5': {'bw': 9999.95, 'delay': 0, 'cpu': 0, 'mem': 0, 'io': {}}, 
    #    '10.0.0.2': {'bw': 9999.98, 'delay': 0.37, 'delay_jitter': 0.062, 'packet_loss': 0, 'cpu': 6.3, 'mem': 81.9, 'io': {3: {'r': 0.0, 'w': 0.0}, 5: {'r': 0.0, 'w': 0.0}}}}
    """
    #看这里↓
    #eval(data) = (0.04, 0, 0.001, 15.6, 91.6, {7: {'r': 0.0, 'w': 0.0}, 1: {'r': 0.0, 'w': 0.0}})
    
    #no, here is the latest
    #(0.05, 0, 0.055, 0.0, 92.5, {7: {'r': 0.0, 'w': 0.0}, 1: {'r': 0.0, 'w': 0.0}}, '192.168.206.181')

    pool = redis.ConnectionPool(host='127.0.0.1', port=6379, db=0)
    r = redis.StrictRedis(connection_pool=pool)
    
    r.set(data[6], str(data[:6]))
    print("%s: %s save completed." % (data[6], str(data[:6])))

    #for key in data.keys():
        #if ip_address == '10.0.0.5':
        #    continue
        #r.set(ip_address, ip_value)
        #print("%s: %s save completed." % (ip_address, ip_value))
