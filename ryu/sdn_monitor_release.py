# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types
from ryu.lib import hub
from operator import attrgetter
import setting
import logging

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        # init logging
        self.name = 'monitor'
        self.logger = logging.getLogger('monitor')
        self.log_mode = logging.DEBUG
        self.logger.setLevel(self.log_mode) #DEBUG = 10, INFO = 20
        
        #file log
        #self.format = logging.Formatter('%(name)s - LINE %(lineno)d - %(levelname)s - %(message)s')
        #self.fh = logging.FileHandler("monitor.log", mode="w", encoding="UTF-8")
        #self.fh.setLevel(logging.INFO)
        #self.fh.setFormatter(self.formatter)
        #self.logger.addHandler(self.fh)
        
        self.mac_to_port = {}
        self.port_to_ip = {}
        self.datapaths = {}
        self.host_info = {}
        self.osd_info = {}
        self.port_features = {} #self.port_features[dpid][p.port_no] = port_feature, port_feature = (config, state, p.curr_speed)
        self.port_stats = {}    #key = (dpid, port_no), value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors, stat.duration_sec, stat.duration_nsec)
        self.flow_stats = {}    #key = (in_port, eth_dst, out_port), value = (packet_count, byte_count, duration_sec, duration_nsec)
        self.flow_speed = {}    #key = (in_port, eth_dst, out_port), speed = byte_count / period
        self.free_bandwidth = {}    #key = (dpid, port_no), speed = free_bw(Mbps)
        
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.port_features.setdefault(dp.id, {})
                self._request_stats(dp)
            print("host_info = %s" % self.host_info)
            hub.sleep(10)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("***EventOFPSwitchFeatures***")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)  #table-miss
        self.logger.info("add_flow(%s, 0, %s, %s) success.", datapath, match, actions)
        self.logger.info("***EventOFPSwitchFeatures done***")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        self.logger.info('--------ofp_event.EventOFPPacketIn--------')
        self.logger.info('ev.msg.msg_len=%s, ev.msg.total_len=%s', ev.msg.msg_len, ev.msg.total_len)
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        ###print('msg.data=', msg.data)#.decode('utf-8', 'ignore'))
        datapath = msg.datapath
        ###print('msg.datapath=', msg.datapath)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        ###print('msg.match[in_port]=', in_port)

        pkt = packet.Packet(msg.data)
        eth_header = pkt.get_protocols(ethernet.ethernet)[0]
        #self.logger.debug('pkt.protocols=', pkt.protocols)

        dst = eth_header.dst
        src = eth_header.src
        ###print('eth_header.dst=', dst, 'eth_header.src=', src)

        dpid = datapath.id
        ###print('datapath.id=', datapath.id)

        arp_header = pkt.get_protocols(arp.arp)
        ip_header = pkt.get_protocol(ipv4.ipv4)
        udp_header = pkt.get_protocol(udp.udp)
        ###print('ip_header=', ip_header, 'udp_header=', udp_header)
        
        if arp_header:
            self.logger.info('***arp_header parser***')
            self.logger.debug("arp_header=%s", arp_header)
            for p in arp_header:
                self.logger.debug("split_p=%s", p)
                key = (dpid, in_port)
                value = p.src_ip
                self.port_to_ip.setdefault(key, value)
                self.logger.info("port_to_ip{key=(%s, %s), value=%s} setdefault completed.", dpid, in_port, value)
            self.logger.info('***arp_header parser done***')

        self.logger.debug("packet in switch %s port %s %s -> %s", dpid, in_port, src, dst)

        # ignore lldp and ipv6 packet
        if eth_header.ethertype == ether_types.ETH_TYPE_LLDP or eth_header.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        if ip_header and udp_header and udp_header.dst_port == 23333:
            self._parse_udp(dpid, in_port, msg.data)
            self._save_udp(self.osd_info, self.port_to_ip, self.host_info)

        #自学习
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid].setdefault(src, -1)
        
        if self.mac_to_port[dpid][src] != in_port:
            self.mac_to_port[dpid][src] = in_port
            self.logger.info("self.mac_to_port[%s][%s] = %s insert completed.", dpid, src, in_port)

        #get out_port, if mac_to_port[dpid][dst] can not found, maybe FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("self.mac_to_port[%s][%s] is not exist, FLOOD to find out_port...", dpid, dst)

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info('Install flow table...')
            #self.logger.info("ofproto.OFPP_FLOOD=%s, out_port=%s", ofproto.OFPP_FLOOD, out_port)
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            #self.logger.info("parser.OFPMatch[in_port=%s, eth_dst=%s, eth_src=%s]", in_port, dst, src)

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                self.logger.info("add_flow(%s, %s, %s, %s, buffer_id=%s) success.", datapath, 1, match, actions, msg.buffer_id)
                return 
            else:
                self.add_flow(datapath, 1, match, actions)
                self.logger.info("add_flow(%s, %s, %s, %s) success.", datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data 
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    #TODO SEND_PACKET_OUT to Ceph Monitor
    def _send_packet_out(self, msg, data):        
        return

    def _parse_udp(self, dpid, in_port, msg_data):
        self.logger.info('***_parse_udp***')
        eth_data = ethernet.ethernet.parser(msg_data)[2]
        ip_data = ipv4.ipv4.parser(eth_data)[2]
        udp_data = udp.udp.parser(ip_data)[2]   #udp_data = b'(0.04, 0, 0.003, 2.0, 89.3, {7: 0.0, 1: 0.0})'
        
        self.logger.debug("ethernet.ethernet.parser(msg_data)=%s", ethernet.ethernet.parser(msg_data))
        self.logger.debug("Get ethernet data = %s", ethernet.ethernet.parser(msg_data)[2])
        self.logger.debug("ipv4.ipv4.parser(eth_data)=%s", ipv4.ipv4.parser(eth_data))
        self.logger.debug("Get ipv4 data = %s", ipv4.ipv4.parser(eth_data)[2])
        self.logger.debug("udp.udp.parser(ip_data)=%s", udp.udp.parser(ip_data))
        self.logger.debug("Get udp data = %s", udp.udp.parser(ip_data)[2])

        #print('_parse_udp:udp_data', udp_data)
        #delay = self._packet_analyze(udp_data)
        key = (dpid, in_port)
        udp_data = udp_data.decode('utf-8')
        self.osd_info[key] = udp_data
        self.logger.info("self.osd_info[%s] = %s insert completed.", key, udp_data)

        self.logger.info('***_parse_udp done***')

    def _save_udp(self, osdinfo, port_to_ip, hostinfo):
        self.logger.info('***_save_udp***')
        for key in port_to_ip.keys():
            if key not in osdinfo:
                continue
            data = eval(osdinfo[key])
            self.logger.debug("osdinfo[%s] = %s", key, data)
            
            hostinfo.setdefault(port_to_ip[key], {'bw':0, 
                                                  'delay': 0, 
                                                  'delay_jitter': 0, 
                                                  'packet_loss': 0,
                                                  'cpu': 0, 
                                                  'mem': 0, 
                                                  'io': {}})
            #print('_save_udp:osdinfo[key]', osdinfo[key])
            #delay, cpu, mem, io = eval(osdinfo[key])
            delay, packet_loss, delay_jitter, cpu, mem, io, _ip_address = data
            hostinfo[port_to_ip[key]]['delay']= delay
            hostinfo[port_to_ip[key]]['delay_jitter']= delay_jitter
            hostinfo[port_to_ip[key]]['packet_loss']= packet_loss
            hostinfo[port_to_ip[key]]['cpu'] = cpu
            hostinfo[port_to_ip[key]]['mem'] = mem
            hostinfo[port_to_ip[key]]['io'] = io
            self.logger.info("hostinfo[%s] = %s insert completed.", port_to_ip[key], hostinfo[port_to_ip[key]])
        
        self.logger.info('***_save_udp done***')
    
    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def _get_speed(self, now_traffic, pre_traffic, period):
        if period:
            return (now_traffic - pre_traffic) / (period)
        else:
            return 0

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)

    def _get_free_bw(self, capacity, speed):
        # capacity: OFPPortDescStatsReply default is kbit/s
        # change it Mbit/s to subtract speed(B/s)
        freebw = max(float(capacity / 1000) - (speed * 8 / 1000000), 0)
        freebw = round(freebw, 2)
        self.logger.debug("_get_free_bw: capacity=%s(kbps), speed=%s(Bps) -> freebw=%s(Mbps)", capacity, speed, freebw)
        return freebw

    #save to self.free_bandwidth[(dpid, port_no)]
    def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        #port_feature <- (config, state, p.curr_speed*100)
        port_state = self.port_features.get(dpid).get(port_no) 
        if port_state:
            #not save Interfaces between switches
            if port_state[2] != 0:
                capacity_speed = port_state[2]
                curr_bw = self._get_free_bw(capacity_speed, speed)
                key = (dpid, port_no)
                if key not in setting.SW_PORT:
                    self.free_bandwidth.setdefault(key, None)
                    self.free_bandwidth[key] = curr_bw  #self.free_bandwidth[(dpid, port_no)] = curr_bw
                    self.logger.info("self.free_bandwidth[%s] = %s insert completed.", key, curr_bw)
        else:
            self.logger.warning("Fail in getting port state")

    #save to host_info[host_ip]['bw'] <- self.free_bandwidth[(dpid, port_no)]
    def _save_ipfreebw(self, free_bandwidth, port_to_ip, hostinfo):
        self.logger.info('***_save_ipfreebw***')
        for key in free_bandwidth.keys():
            if key not in port_to_ip:
                self.logger.info("_save_ipfreebw: cannot found self.port_to_ip[%s], continue...", key)
                continue
            hostinfo.setdefault(port_to_ip[key], {'bw':0, 'delay':0, 'cpu':0, 'mem':0, 'io':{}})
            hostinfo[port_to_ip[key]]['bw'] = free_bandwidth[key]
            self.logger.info("self.host_info[%s]['bw'] = %s insert completed.", key, free_bandwidth[key])
        self.logger.info('***_save_ipfreebw done***')

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Record datapath's info
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.info('register datapath %016x completed.', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath %016x completed.', datapath.id)
                del self.datapaths[datapath.id]

    #send stats request msg to datapath
    #完成控制器主动下发逻辑
    def _request_stats(self, datapath):
        self.logger.info('***_request_stats***')
        self.logger.info("datapath %016x sending stats request.", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        self.logger.info('***_request_stats done***')

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            Save port description info.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",             
                       ofproto.OFPPC_NO_RECV: "No Recv",            
                       ofproto.OFPPC_NO_FWD: "No Forward",          
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}  

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",      
                      ofproto.OFPPS_BLOCKED: "Blocked",     
                      ofproto.OFPPS_LIVE: "Live"}           
        
        self.logger.info('***EventOFPPortDescStatsReply***')
        ports = []
        for p in ev.msg.body:
            if(p.port_no == ofproto_v1_3.OFPP_LOCAL):   #4294967294
                continue
            
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))
            """
            print(ports)
            """

            self.logger.debug('port_no=%d hw_addr=%s name=%s config=0x%08x '
                             'state=0x%08x curr=0x%08x advertised=0x%08x '
                             'supported=0x%08x peer=0x%08x curr_speed=%d '
                             'max_speed=%d' %
                            (p.port_no, p.hw_addr,
                            p.name, p.config,
                            p.state, p.curr, p.advertised,
                            p.supported, p.peer, p.curr_speed,
                            p.max_speed))

            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "Up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "Others"

            port_feature = (config, state, p.curr_speed)    #port_feature[2](kbps)

            self.port_features[dpid][p.port_no] = port_feature
            self.logger.info("self.port_features[%s][%s] = %s insert completed.", dpid, p.port_no, port_feature)
        self.logger.info('***EventOFPPortDescStatsReply done***')

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
            Save port's stats info
            Calculate port's speed and save it.
        """
        """
        for stat in ev.msg.body:
            if(stat.port_no == ofproto_v1_3.OFPP_LOCAL):   #4294967294
                continue
            self.logger.debug('Get port_no=%d, '
                              'rx_packets=%d, tx_packets=%d, '
                              'rx_bytes=%d, tx_bytes=%d, '
                              'rx_dropped=%d, tx_dropped=%d, '
                              'rx_errors=%d, tx_errors=%d, '
                              'rx_frame_err=%d, rx_over_err=%d rx_crc_err=%d, '
                              'collisions=%d, duration_sec=%d duration_nsec=%d.' %
                            (stat.port_no, 
                            stat.rx_packets, stat.tx_packets,       
                            stat.rx_bytes, stat.tx_bytes,           
                            stat.rx_dropped, stat.tx_dropped,       
                            stat.rx_errors, stat.tx_errors,         
                            stat.rx_frame_err, stat.rx_over_err,    
                            stat.rx_crc_err, stat.collisions,      
                            stat.duration_sec, stat.duration_nsec)) 
        """
        
        self.logger.info('***EventOFPPortStatsReply***')
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        """
        self.logger.debug('ev.msg.body=', body)
        """
        
        for stat in sorted(body, key=attrgetter('port_no')):    #sort按port_no的值排序
            port_no = stat.port_no
            
            if port_no == ofproto_v1_3.OFPP_LOCAL:
                continue
            
            key = (dpid, port_no)
            value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors, 
                    stat.duration_sec, stat.duration_nsec)

            self._save_stats(self.port_stats, key, value, 5)                
            self.logger.info("self.port_stats[%s] = %s insert completed.", key, value) 

            # Get port speed.
            pre_traffic = 0 
            period = setting.MONITOR_PERIOD
            port_stats_value = self.port_stats[key]
            
            if len(port_stats_value) > 1:
                pre_traffic = port_stats_value[-2][0] + port_stats_value[-2][1]
                period = self._get_period(port_stats_value[-1][3], port_stats_value[-1][4],
                                          port_stats_value[-2][3], port_stats_value[-2][4])
            
            now_traffic = self.port_stats[key][-1][0] + self.port_stats[key][-1][1]
            speed = self._get_speed(now_traffic, pre_traffic, period)

            self._save_freebandwidth(dpid, port_no, speed)
        
        # save ip free bandwidth
        self._save_ipfreebw(self.free_bandwidth, self.port_to_ip, self.host_info)

        self.logger.info('***EventOFPPortStatsReply done***')

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply info into self.flow_stats.
            Calculate flow speed and Save it.
        """
        """
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                        'duration_sec=%d duration_nsec=%d '
                        'priority=%d '
                        'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                        'cookie=%d packet_count=%d byte_count=%d '
                        'match=%s instructions=%s' %
                        (stat.table_id,                                     
                        stat.duration_sec, stat.duration_nsec,              
                        stat.priority,                                      
                        stat.idle_timeout,                                  
                        stat.hard_timeout,                                  
                        stat.flags,
                        stat.cookie, 
                        stat.packet_count, stat.byte_count,                 
                        stat.match,                                         
                        stat.instructions))                                 

        self.logger.debug('Flows: %s', flows)
        """
        
        self.logger.info('***EventOFPFlowStatsReply***')
        
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        #self.logger.debug('ev.msg.body =', body)
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})

        for stat in sorted([flow for flow in body if flow.priority == 1 or 0],   
                           key=lambda flow: (flow.match.get('in_port'),     
                                             flow.match.get('eth_dst'))):  
            #self.logger.debug('stat =', stat)
            #key = (in_port, eth_dst, out_port)
            key = (stat.match['in_port'], stat.match['eth_dst'],
                   stat.instructions[0].actions[0].port)
            #value = (packet_count, byte_count, duration_sec, duration_nsec)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)
            self.logger.info("self.flow_stats[%s][%s] = %s insert completed.", dpid, key, value)
            
            self.logger.debug('self.flow_stats[%s][%s].len = %d', dpid, key, len(self.flow_stats[dpid][key]))
            self.logger.debug('self.flow_stats[%s][%s] = %s', dpid, key, self.flow_stats[dpid][key])

            # Get flow's speed.
            pre_byte_count = 0
            period = setting.MONITOR_PERIOD #default = 2
            flow_stats_value = self.flow_stats[dpid][key]
            if len(flow_stats_value) > 1:
                pre_byte_count = flow_stats_value[-2][1]
                period = self._get_period(flow_stats_value[-1][2], flow_stats_value[-1][3],
                                          flow_stats_value[-2][2], flow_stats_value[-2][3])

            now_byte_count = self.flow_stats[dpid][key][-1][1]
            speed = self._get_speed(now_byte_count, pre_byte_count, period)

            self._save_stats(self.flow_speed[dpid], key, speed, 5)
            self.logger.info("self.flow_speed[%s][%s] = %s Byte(s) insert completed.", dpid, key, speed) 

        self.logger.info('***EventOFPFlowStatsReply done***')

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto

        """
        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'
        """
        
        dpid = dp.id
        reason = msg.reason
        port_no = msg.desc.port_no
        
        reason_dict = {ofproto.OFPPR_ADD: "added",
                    ofproto.OFPPR_DELETE: "deleted",
                    ofproto.OFPPR_MODIFY: "modified", }
        
        if reason in reason_dict:
            self.logger.info('switch %0x16 port %s %s.', dpid, port_no, reason_dict[reason])
        else:
            self.logger.warning('switch %0x16 port %s %s.', dpid, port_no, reason_dict[reason])
        
        self.logger.debug('OFPPortStatus received: reason=%s desc=%s', reason, msg.desc)

