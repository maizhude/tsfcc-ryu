from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp, ipv4
from ryu.lib.packet import ether_types
import time
import threading


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.datapath_to_ports = {}
        # 创建一个字典，用于存储TCP流的信息
        self.tcp_flows = {}
        self.elephant_flows = {}

        #开启定时器
        self.timer = threading.Timer(1, self.send_queue_length_request)
        self.timer.start()
    
    def send_queue_length_request(self):
        for dpid,datapath in self.datapaths.items():
            # 构造一个echo_request消息
            ofp_parser = datapath.ofproto_parser
            for port_no in self.datapath_to_ports[dpid]:
                quelen_req = ofp_parser.OFPQueueLengthRequest(datapath, data=port_no)

                # 发送echo_request消息到交换机
                datapath.send_msg(quelen_req)

        # 重新启动定时器
        self.timer = threading.Timer(1, self.send_queue_length_request)
        self.timer.start()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.logger.info(datapath)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
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
        self.add_flow(datapath, 10, syn_match, tcp_actions)
        self.add_flow(datapath, 10, syn_ack_match, tcp_actions)
        self.add_flow(datapath, 10, fin_psh_match, tcp_actions)
        self.add_flow(datapath, 10, fin_match, tcp_actions)
    
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
        #todo 删除流表 前两种方法都是错的，
        # mod = parser.OFPFlowMod(
        #     datapath=datapath, match=match, cookie=0,
        #     command=ofproto.OFPFC_DELETE)
        # mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofproto.OFPFC_DELETE, 0, 0, 20,
        #                 ofproto.OFP_NO_BUFFER, 0, ofproto.OFPG_ANY,
        #                 ofproto.OFPFF_SEND_FLOW_REM, match=match)
        mod = parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)
    
    #处理队列长度恢复到阈值之下的事件
    @set_ev_cls(ofp_event.EventOFPBufCr,MAIN_DISPATCHER)
    def _buf_cr_handler(self,ev):
        msg = ev.msg
        info = msg.data
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        port_no = int.from_bytes(info[0:4],byteorder='big')
        switch_id = datapath.id
        self.logger.info("恢复交换机id:%d", switch_id)
        parser = datapath.ofproto_parser
        for key in self.tcp_flows.keys():
            if switch_id in self.tcp_flows[key]['switches'].keys():
                if self.tcp_flows[key]['switches'][switch_id]['out_port'] == port_no:
                    ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                    if ack_key in self.tcp_flows:
                        match = parser.OFPMatch(
                        eth_type=0x0800,ip_proto=6,  # 表示TCP协议
                        ipv4_src=self.tcp_flows[ack_key]['src_ip'],ipv4_dst=self.tcp_flows[ack_key]['dst_ip'],
                        tcp_src=self.tcp_flows[ack_key]['src_port'],tcp_dst=self.tcp_flows[ack_key]['dst_port']
                        )
                        self.del_flow(datapath, match)
    
    #处理队列长度超过阈值事件
    @set_ev_cls(ofp_event.EventOFPBufCn,MAIN_DISPATCHER)
    def _buf_cn_handler(self,ev):
        msg = ev.msg
        info = msg.data
        datapath = msg.datapath
        switch_id = datapath.id
        parser = datapath.ofproto_parser
        port_no = int.from_bytes(info[0:4],byteorder='big')
        port_buf = int.from_bytes(info[112:116],'little')

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
        ql = 120
        qh = 160
        rtt = 0.08
        bandwitdth = 1.5*1024*1024
        mss = 1460
        # 更新TCP流的存在时间
        for key in self.tcp_flows.keys():
            n += 1
            self.tcp_flows[key]['exist_time'] = time.time() - self.tcp_flows[key]['start_time']

            #判断是否是大象流，并添加到大象数据结构中，删除原来的数据
            if self.tcp_flows[key]['exist_time'] > 1:
                b += 1
                if key not in self.elephant_flows:
                    self.elephant_flows[key] = self.tcp_flows[key]
                else:
                    self.elephant_flows[key]['exist_time'] = self.tcp_flows[key]['exist_time']
                # self.logger.info(self.elephant_flows)
        a = n - b
        swnd = (rtt * bandwitdth)/(8*n)
        #todo 队列长度大于L小于QL
        if port_buf < ql :
            print(111)
            rwnd = max(int(2*swnd/3), mss)
            for key in self.elephant_flows.keys():
                if self.elephant_flows[key]['switches'][switch_id]['out_port'] == port_no :
                    ack_key = (self.elephant_flows[key]['dst_ip'], self.elephant_flows[key]['src_ip'], self.elephant_flows[key]['dst_port'], self.elephant_flows[key]['src_port'])
                    if ack_key in self.tcp_flows:
                        elephant_match = parser.OFPMatch(
                        eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                        ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                        tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                        out_port = self.tcp_flows[ack_key]['switches'][switch_id]['out_port']
                        actions = [parser.OFPActionSetRWND(rwnd), parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, 12, elephant_match, actions)
        #todo 队列长度大于QL小于QH
        elif port_buf < qh :
            print(222)
            rwnd = max(int(swnd/2), mss)
            for key in self.elephant_flows.keys():
                if self.elephant_flows[key]['switches'][switch_id]['out_port'] == port_no:
                    ack_key = (self.elephant_flows[key]['dst_ip'], self.elephant_flows[key]['src_ip'], self.elephant_flows[key]['dst_port'], self.elephant_flows[key]['src_port'])
                    if ack_key in self.tcp_flows:
                        elephant_match = parser.OFPMatch(
                        eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                        ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                        tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                        out_port = self.tcp_flows[ack_key]['switches'][switch_id]['out_port']
                        actions = [parser.OFPActionSetRWND(rwnd), parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, 12, elephant_match, actions)
        #todo 队列长度大于QH
        else:
            print(333)
            elephant_rwnd = mss
            mouse_rwnd = max(int((n*swnd-a*mss)/b), mss)
            for key in self.elephant_flows.keys():
                if self.elephant_flows[key]['switches'][switch_id]['out_port'] == port_no:
                    ack_key = (self.elephant_flows[key]['dst_ip'], self.elephant_flows[key]['src_ip'], self.elephant_flows[key]['dst_port'], self.elephant_flows[key]['src_port'])
                    if ack_key in self.tcp_flows:
                        elephant_match = parser.OFPMatch(
                        eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                        ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                        tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                        out_port = self.tcp_flows[ack_key]['switches'][switch_id]['out_port']
                        actions = [parser.OFPActionSetRWND(elephant_rwnd), parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, 12, elephant_match, actions)
            for key in self.tcp_flows.keys():
                if self.tcp_flows[key]['exist_time'] <= 1 and self.tcp_flows[key]['switches'][switch_id]['out_port'] == port_no:
                    ack_key = (self.tcp_flows[key]['dst_ip'], self.tcp_flows[key]['src_ip'], self.tcp_flows[key]['dst_port'], self.tcp_flows[key]['src_port'])
                    if ack_key in self.tcp_flows:
                        elephant_match = parser.OFPMatch(
                        eth_type=0x0800, ip_proto=6, ipv4_src=self.tcp_flows[ack_key]['src_ip'], 
                        ipv4_dst=self.tcp_flows[ack_key]['dst_ip'], tcp_src=self.tcp_flows[ack_key]['src_port'],
                        tcp_dst=self.tcp_flows[ack_key]['dst_port'])
                        out_port = self.tcp_flows[ack_key]['switches'][switch_id]['out_port']
                        actions = [parser.OFPActionSetRWND(mouse_rwnd), parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, 12, elephant_match, actions)
    
    #处理packet_in事件的方法
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        #从数据包中获取mac地址
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        if datapath.id not in self.datapath_to_ports:
            self.datapath_to_ports[datapath.id] = []
        elif in_port not in self.datapath_to_ports[datapath.id]:
            self.datapath_to_ports[datapath.id].append(in_port)
        # self.logger.info(self.datapath_to_ports)

        dpid = format(datapath.id, "d").zfill(16)
        if datapath.id not in self.datapaths:
            self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]


    
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
                #self.logger.info(1)
                # 检查是否已经存在该TCP流
                if flow_id not in self.tcp_flows:
                    # 如果不存在，创建一个新的TCP流记录
                    self.tcp_flows[flow_id] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'id': flow_id,
                        'size': 0,
                        'start_time': time.time(),
                        'switches': {}
                    }
                # 更新TCP流的大小
                    self.tcp_flows[flow_id]['size'] += len(pkt)
                
                # 更新TCP流经过的交换机列表
                switch_id = ev.msg.datapath.id
                in_port = msg.match["in_port"]
                if switch_id not in self.tcp_flows[flow_id]['switches']:
                    self.tcp_flows[flow_id]['switches'][switch_id] = {
                            "in_port": in_port,
                            "out_port": out_port
                        }
                #self.logger.info(self.tcp_flows)
            # todo FIN-ACK表示删除数据结构
            elif tcp_flags & tcp.TCP_FIN:
                #self.logger.info(2)
                if flow_id in self.tcp_flows:
                    # 如果在普通流表中存在，删除该TCP流记录
                    del self.tcp_flows[flow_id]
                if flow_id in self.elephant_flows:
                    # 如果在大象流表中存在，删除该TCP流记录
                    del self.elephant_flows[flow_id]
                #self.logger.info(self.tcp_flows)
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
