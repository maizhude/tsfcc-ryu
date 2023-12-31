# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
from ryu.lib.packet import tcp, ipv4
from ryu.lib.packet.tcp import TCPOptionMaximumSegmentSize, TCPOptionWindowScale
import time
import threading


class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']
        self.datapaths = {}
        self.datapath_to_ports = {}
        # 创建一个字典，用于存储TCP流的信息
        self.tcp_flows = {}
        self.elephant_flows = {}

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)
        #开启定时器
        # self.timer1 = threading.Timer(1, self.send_queue_length_request)
        # self.timer1.start()
        self.timer2 = threading.Timer(1, self.flow_status_time_expired)
        self.timer2.start()
    
    #隔一段时间查询每个交换机每个端口的队列长度
    # def send_queue_length_request(self):
    #     for dpid,datapath in self.datapaths.items():
    #         # 构造一个echo_request消息
    #         ofp = datapath.ofproto
    #         ofp_parser = datapath.ofproto_parser
    #         for port_no in self.datapath_to_ports[dpid]:
    #             # self.logger.info(port_no)
    #             quelen_req = ofp_parser.OFPQueueLengthRequest(datapath, data=port_no)

    #             # 发送echo_request消息到交换机
    #             datapath.send_msg(quelen_req)

    #     # 重新启动定时器
    #     self.timer1 = threading.Timer(1, self.send_queue_length_request)
    #     self.timer1.start()
    
    #incast预测时间超时，隔一段时间判断一下新流的大小占总流大小比例，判断是否可能发送拥塞
    def flow_status_time_expired(self):
        for dpid,datapath in self.datapaths.items():
            for port_no in self.datapath_to_ports[dpid]:
                new_flow = self.datapath_to_ports[dpid][port_no]["new_flow"]
                total_flow = self.datapath_to_ports[dpid][port_no]["total_flow"]
                if total_flow != 0 and new_flow > 7:
                    self.logger.info("incast预测拥塞效果实现")
                    self.forecast_incast_congestion(datapath,port_no,total_flow)
                    self.datapath_to_ports[dpid][port_no]["state"] = 1
                    self.datapath_to_ports[dpid][port_no]["count"] = 0
                else:
                    if self.datapath_to_ports[dpid][port_no]["state"] == 1:
                        self.datapath_to_ports[dpid][port_no]["count"] += 1
                    if self.datapath_to_ports[dpid][port_no]["count"] == 1:
                        self.incast_congestion_recover(datapath,port_no)
                        self.datapath_to_ports[dpid][port_no]["state"] = 0
                        self.datapath_to_ports[dpid][port_no]["count"] = 0
                self.datapath_to_ports[dpid][port_no]["new_flow"] = 0
        self.timer2 = threading.Timer(1, self.flow_status_time_expired)
        self.timer2.start()
    
    #incast发送拥塞的处理，rwnd=swnd，轻微处理拥塞
    def forecast_incast_congestion(self, datapath, port_no, total_flow):
        rtt = 0.0012
        bandwitdth = 1000*1024*1024
        parser = datapath.ofproto_parser
        switch_id = datapath.id
        swnd = (rtt * bandwitdth)/(8*total_flow)
        for key in list(self.tcp_flows.keys()):
                if switch_id in self.tcp_flows[key]['switches'].keys():
                    if self.tcp_flows[key]['switches'][switch_id]['out_port'] == port_no :
                        ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                        if ack_key in self.tcp_flows:
                            shift_cnt = self.tcp_flows[ack_key]['shift_cnt']
                            window_scale = 2**shift_cnt
                            rwnd = int(swnd/window_scale)
                            out_swid = list(self.tcp_flows[key]['switches'].keys())[0]
                            add_datapath = datapath
                            if out_swid in self.datapaths.keys():
                                add_datapath = self.datapaths[out_swid]
                            elephant_match = parser.OFPMatch(
                            eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                            ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                            tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                            out_port = self.tcp_flows[key]['switches'][out_swid]['in_port']
                            actions = [parser.OFPActionSetRWND(rwnd), parser.OFPActionOutput(out_port)]
                            self.add_flow(add_datapath, 11, elephant_match, actions)
    
    def incast_congestion_recover(self,datapath,port_no):
        switch_id = datapath.id
        parser = datapath.ofproto_parser
        for key in list(self.tcp_flows.keys()):
            if switch_id in self.tcp_flows[key]['switches'].keys():
                if self.tcp_flows[key]['switches'][switch_id]['out_port'] == port_no:
                    ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                    if ack_key in self.tcp_flows:
                        out_swid = list(self.tcp_flows[key]['switches'].keys())[0]
                        if out_swid in self.datapaths.keys():
                            del_datapath = self.datapaths[out_swid]
                            match = parser.OFPMatch(
                            eth_type=0x0800,ip_proto=6,  # 表示TCP协议
                            ipv4_src=self.tcp_flows[ack_key]['src_ip'],ipv4_dst=self.tcp_flows[ack_key]['dst_ip'],
                            tcp_src=self.tcp_flows[ack_key]['src_port'],tcp_dst=self.tcp_flows[ack_key]['dst_port']
                            )
                            self.del_flow(del_datapath, match)
        
    #交换机连接到控制器时的处理函数
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        if datapath.id not in self.datapath_to_ports:
            self.datapath_to_ports[datapath.id] = {}
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
        self.add_flow(datapath, 0, match, actions)
        #为每个交换机添加识别SYN和FIN的流表
        syn_match = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,  # 表示TCP协议
                tcp_flags=tcp.TCP_SYN
                )
        syn_ack_match = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,  # 表示TCP协议
                tcp_flags=tcp.TCP_SYN | tcp.TCP_ACK
                )
        fin_match = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,  # 表示TCP协议
                tcp_flags=tcp.TCP_FIN | tcp.TCP_ACK
                )
        fin_psh_match = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,  # 表示TCP协议
                tcp_flags=tcp.TCP_FIN | tcp.TCP_ACK | tcp.TCP_PSH
                )
        tcp_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 65534, syn_match, tcp_actions)
        self.add_flow(datapath, 65534, syn_ack_match, tcp_actions)
        self.add_flow(datapath, 65534, fin_psh_match, tcp_actions)
        self.add_flow(datapath, 65534, fin_match, tcp_actions)
    
    #添加流表
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
    
    #删除流表
    def del_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    #数据包到达时的处理函数
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        #给datapath_to_ports初始化一些数据
        if datapath.id not in self.datapath_to_ports:
            self.datapath_to_ports[datapath.id] = []
        else:
            if in_port not in self.datapath_to_ports[datapath.id]:
                self.datapath_to_ports[datapath.id][in_port] = {"new_flow":0, "total_flow":0,"state":0,"count":0}
            if out_port != ofproto.OFPP_FLOOD and out_port not in self.datapath_to_ports[datapath.id]:
                self.datapath_to_ports[datapath.id][out_port] = {"new_flow":0, "total_flow":0,"state":0,"count":0}
        # self.logger.info(self.datapath_to_ports)

        # 获取TCP头部信息
        tcp_header = pkt.get_protocol(tcp.tcp)

        # 检查是否是TCP数据包
        if tcp_header is not None:
            # 获取源地址、目的地址、源端口号和目的端口号
            src_ip = pkt.get_protocol(ipv4.ipv4).src
            dst_ip = pkt.get_protocol(ipv4.ipv4).dst
            src_port = tcp_header.src_port
            dst_port = tcp_header.dst_port
            tcp_flags = tcp_header.bits
            
            flow_id = (src_ip, dst_ip, src_port, dst_port)
            # todo SYN或SYN-ACK表示添加一个新流到控制器数据结构
            if tcp_flags & tcp.TCP_SYN:
                #新流和总流加一
                if out_port != ofproto.OFPP_FLOOD:
                    self.datapath_to_ports[datapath.id][out_port]["new_flow"] += 1
                    self.datapath_to_ports[datapath.id][out_port]["total_flow"] += 1
                # 检查是否已经存在该TCP流
                if flow_id not in self.tcp_flows:
                    # 如果不存在，创建一个新的TCP流记录
                    self.tcp_flows[flow_id] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'max_size': 1460,
                        'shift_cnt': 0,
                        'size': 0,
                        'start_time': time.time(),
                        'exist_time': 0,
                        'switches': {}
                    }
                # 更新TCP流的大小
                # self.tcp_flows[flow_id]['size'] += len(pkt)

                # 获取窗口缩放选项字段
                # 遍历option列表
                for opt in tcp_header.option:
                    # 如果是Maximum Segment Size选项
                    if isinstance(opt, TCPOptionMaximumSegmentSize):
                        # 获取max_seg_size
                        max_seg_size = opt.max_seg_size
                        self.tcp_flows[flow_id]['max_size'] = max_seg_size
                    # 如果是Window Scale选项
                    elif isinstance(opt, TCPOptionWindowScale):
                        # 获取shift_cnt
                        shift_cnt = opt.shift_cnt
                        self.tcp_flows[flow_id]['shift_cnt'] = shift_cnt
                # 更新TCP流经过的交换机列表
                switch_id = ev.msg.datapath.id
                in_port = msg.match["in_port"]
                if switch_id not in self.tcp_flows[flow_id]['switches']:
                    self.tcp_flows[flow_id]['switches'][switch_id] = {
                            "in_port": in_port,
                            "out_port": out_port
                        }
                # self.logger.info(self.tcp_flows)
            # todo FIN-ACK表示删除数据结构
            elif tcp_flags & tcp.TCP_FIN:
                #self.logger.info(2)
                if out_port != ofproto.OFPP_FLOOD:
                    self.datapath_to_ports[datapath.id][out_port]["new_flow"] = max(self.datapath_to_ports[datapath.id][out_port]["new_flow"]-1,0)
                    self.datapath_to_ports[datapath.id][out_port]["total_flow"] = max(self.datapath_to_ports[datapath.id][out_port]["total_flow"]-1,0)
                if flow_id in self.tcp_flows:
                    # 如果在普通流表中存在，删除该TCP流记录
                    out_swid =  list(self.tcp_flows[flow_id]['switches'].keys())[-1]
                    if out_swid in self.datapaths.keys():
                        del_datapath = self.datapaths[out_swid]
                        match = parser.OFPMatch(
                        eth_type=0x0800,ip_proto=6,  # 表示TCP协议
                        ipv4_src=self.tcp_flows[flow_id]['src_ip'],ipv4_dst=self.tcp_flows[flow_id]['dst_ip'],
                        tcp_src=self.tcp_flows[flow_id]['src_port'],tcp_dst=self.tcp_flows[flow_id]['dst_port']
                        )
                        self.del_flow(del_datapath, match)
                    del self.tcp_flows[flow_id]
                if flow_id in self.elephant_flows:
                    # 如果在大象流表中存在，删除该TCP流记录
                    out_swid =  list(self.elephant_flows[flow_id]['switches'].keys())[-1]
                    if out_swid in self.datapaths.keys():
                        del_datapath = self.datapaths[out_swid]
                        match = parser.OFPMatch(
                        eth_type=0x0800,ip_proto=6,  # 表示TCP协议
                        ipv4_src=self.elephant_flows[flow_id]['src_ip'],ipv4_dst=self.elephant_flows[flow_id]['dst_ip'],
                        tcp_src=self.elephant_flows[flow_id]['src_port'],tcp_dst=self.elephant_flows[flow_id]['dst_port']
                        )
                        self.del_flow(del_datapath, match)
                    del self.elephant_flows[flow_id]
                #self.logger.info(self.tcp_flows)

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        # self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        # self.logger.debug("[dpid=%s][port=%d] state=%s",
        #                   dpid_str, ev.port_no, of_state[ev.port_state])


    #处理队列长度恢复到阈值之下的事件
    @set_ev_cls(ofp_event.EventOFPBufCr,MAIN_DISPATCHER)
    def _buf_cr_handler(self,ev):
        msg = ev.msg
        info = msg.data
        datapath = msg.datapath
        switch_id = datapath.id
        self.logger.info("恢复交换机id:%d", switch_id)
        parser = datapath.ofproto_parser
        port_no = int.from_bytes(info[0:4],byteorder='little')
        for key in list(self.tcp_flows.keys()):
            if switch_id in self.tcp_flows[key]['switches'].keys():
                if self.tcp_flows[key]['switches'][switch_id]['out_port'] == port_no:
                    ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                    if ack_key in self.tcp_flows:
                        out_swid =  list(self.tcp_flows[key]['switches'].keys())[0]
                        del_datapath = datapath
                        if out_swid in self.datapaths.keys():
                            del_datapath = self.datapaths[out_swid]
                        match = parser.OFPMatch(
                        eth_type=0x0800,ip_proto=6,  # 表示TCP协议
                        ipv4_src=self.tcp_flows[ack_key]['src_ip'],ipv4_dst=self.tcp_flows[ack_key]['dst_ip'],
                        tcp_src=self.tcp_flows[ack_key]['src_port'],tcp_dst=self.tcp_flows[ack_key]['dst_port']
                        )
                        self.del_flow(del_datapath, match)
       
    
    #处理队列长度超过阈值事件
    @set_ev_cls(ofp_event.EventOFPBufCn,MAIN_DISPATCHER)
    def _buf_cn_handler(self,ev):
        msg = ev.msg
        info = msg.data
        datapath = msg.datapath
        switch_id = datapath.id
        parser = datapath.ofproto_parser
        port_no = int.from_bytes(info[0:4],byteorder='little')
        port_buf = int.from_bytes(info[112:116],'little')
        self.logger.info("拥塞交换机:%d,拥塞端口:%d,队列长度:%d",switch_id, port_no,port_buf)
        # port_no = int.from_bytes(info[0:4],byteorder='big')
        # rx_packets = int.from_bytes(info[8:16],'little')
        # tx_packets = int.from_bytes(info[16:24],'little')
        # rx_bytes = int.from_bytes(info[24:32],'little')
        # tx_bytes = int.from_bytes(info[32:40],'little')
        # rx_dropped = int.from_bytes(info[40:48],'little')
        # tx_dropped = int.from_bytes(info[48:56],'little')
        # rx_errors = int.from_bytes(info[56:64],'little')
        # tx_errors = int.from_bytes(info[64:72],'little')
        # rx_frame_err = int.from_bytes(info[72:80],'little')
        # rx_over_err = int.from_bytes(info[80:88],'little')
        # rx_crc_err = int.from_bytes(info[88:96],'little')
        # collisions = int.from_bytes(info[96:104],'little')
        # duration_sec = int.from_bytes(info[104:108],'little')
        # duration_nsec = int.from_bytes(info[108:112],'little')
        # port_buf = int.from_bytes(info[112:116],'little')
        # priority = int.from_bytes(info[116:118],'little')
        # cookie = int.from_bytes(info[120:128],'little')
        
        n = 0
        a = 0
        b = 0
        ql = 150
        qh = 240
        rtt = 0.0012
        bandwitdth = 1000*1024*1024
        mss = 1460
        # 更新TCP流的存在时间
        for key in list(self.tcp_flows.keys()):
            if switch_id in self.tcp_flows[key]['switches'].keys():
                if self.tcp_flows[key]['switches'][switch_id]['out_port'] == port_no :
                    n += 1
                    self.tcp_flows[key]['exist_time'] = time.time() - self.tcp_flows[key]['start_time']

                    #判断是否是大象流，并添加到大象数据结构中，删除原来的数据
                    if self.tcp_flows[key]['exist_time'] > 1:
                        b += 1
                        if key not in self.elephant_flows:
                            self.elephant_flows[key] = self.tcp_flows[key]
                        else:
                            self.elephant_flows[key]['exist_time'] = self.tcp_flows[key]['exist_time']
                        # self.logger.info(self.elephant_flows.keys())
        a = n - b
        if n != 0:
            swnd = (rtt * bandwitdth + port_buf * 1500 * 8)/(8*n)
            #todo 队列长度大于L小于QL
            if port_buf < ql :
                print(111)
                for key in list(self.elephant_flows.keys()):
                    if switch_id in self.elephant_flows[key]['switches'].keys():
                        if self.elephant_flows[key]['switches'][switch_id]['out_port'] == port_no :
                            ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                            if ack_key in self.tcp_flows:
                                shift_cnt = self.tcp_flows[ack_key]['shift_cnt']
                                mss = self.tcp_flows[ack_key]['max_size']
                                window_scale = 2**shift_cnt
                                rwnd = max(int(2*swnd/(3*window_scale)), int(mss/window_scale))
                                out_swid =  list(self.tcp_flows[key]['switches'].keys())[0]
                                add_datapath = datapath
                                if out_swid in self.datapaths.keys():
                                    add_datapath = self.datapaths[out_swid]
                                elephant_match = parser.OFPMatch(
                                eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                                ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                                tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                                out_port = self.tcp_flows[key]['switches'][out_swid]['in_port']
                                actions = [parser.OFPActionSetRWND(rwnd), parser.OFPActionOutput(out_port)]
                                self.add_flow(add_datapath, 12, elephant_match, actions)
            #todo 队列长度大于QL小于QH
            elif port_buf < qh :
                print(222)
                for key in list(self.elephant_flows.keys()):
                    if switch_id in self.elephant_flows[key]['switches'].keys():
                        if self.elephant_flows[key]['switches'][switch_id]['out_port'] == port_no:
                            ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                            if ack_key in self.tcp_flows:
                                shift_cnt = self.tcp_flows[ack_key]['shift_cnt']
                                mss = self.tcp_flows[ack_key]['max_size']
                                window_scale = 2**shift_cnt
                                rwnd = max(int(swnd/(2*window_scale)), int(mss/window_scale))
                                out_swid =  list(self.tcp_flows[key]['switches'].keys())[0]
                                add_datapath = datapath
                                if out_swid in self.datapaths.keys():
                                    add_datapath = self.datapaths[out_swid]
                                elephant_match = parser.OFPMatch(
                                eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                                ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                                tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                                out_port = self.tcp_flows[key]['switches'][out_swid]['in_port']
                                actions = [parser.OFPActionSetRWND(rwnd), parser.OFPActionOutput(out_port)]
                                self.add_flow(add_datapath, 12, elephant_match, actions)
                            
            #todo 队列长度大于QH
            else:
                print(333)
                for key in list(self.elephant_flows.keys()):
                    if switch_id in self.elephant_flows[key]['switches'].keys():
                        if self.elephant_flows[key]['switches'][switch_id]['out_port'] == port_no:
                            ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                            if ack_key in self.tcp_flows:
                                shift_cnt = self.tcp_flows[ack_key]['shift_cnt']
                                mss = self.tcp_flows[ack_key]['max_size']
                                window_scale = 2**shift_cnt
                                elephant_rwnd = int(mss/window_scale)
                                out_swid =  list(self.tcp_flows[key]['switches'].keys())[0]
                                add_datapath = datapath
                                if out_swid in self.datapaths.keys():
                                    add_datapath = self.datapaths[out_swid]
                                elephant_match = parser.OFPMatch(
                                eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                                ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                                tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                                out_port = self.tcp_flows[key]['switches'][out_swid]['in_port']
                                actions = [parser.OFPActionSetRWND(elephant_rwnd), parser.OFPActionOutput(out_port)]
                                self.add_flow(add_datapath, 12, elephant_match, actions)
                for key in list(self.tcp_flows.keys()):
                    if switch_id in self.tcp_flows[key]['switches'].keys():
                        
                        if b > 0 and self.tcp_flows[key]['switches'][switch_id]['out_port'] == port_no and self.tcp_flows[key]['exist_time'] <= 1:
                            ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                            if ack_key in self.tcp_flows:
                                shift_cnt = self.tcp_flows[ack_key]['shift_cnt']
                                mss = self.tcp_flows[ack_key]['max_size']
                                window_scale = 2**shift_cnt
                                mouse_rwnd = max(int((n*swnd-a*mss)/(b*window_scale)), int(mss/window_scale))
                                out_swid =  list(self.tcp_flows[key]['switches'].keys())[0]
                                add_datapath = datapath
                                if out_swid in self.datapaths.keys():
                                    add_datapath = self.datapaths[out_swid]
                                elephant_match = parser.OFPMatch(
                                eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                                ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                                tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                                out_port = self.tcp_flows[key]['switches'][out_swid]['in_port']
                                actions = [parser.OFPActionSetRWND(mouse_rwnd), parser.OFPActionOutput(out_port)]
                                self.add_flow(add_datapath, 12, elephant_match, actions)
        