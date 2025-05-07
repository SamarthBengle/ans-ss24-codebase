#!/usr/bin/env python3
"""
 Copyright 2024 Computer Networks Group @ UPB
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
      https://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

class SwitchRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchRouter, self).__init__(*args, **kwargs)
        # For switch learning (maps datapath_id -> {mac_addr -> port})
        self.mac_to_port = {}
        
        # For router (IP -> MAC mapping)
        self.arp_table = {}
        
        # Router's MAC addresses for each port
        self.port_to_mac = {
            1: "00:00:00:00:01:01",  # Router port facing s1
            2: "00:00:00:00:01:02",  # Router port facing s2
            3: "00:00:00:00:01:03"   # Router port facing ext
        }
        
        # Router's IP addresses for each port
        self.port_to_ip = {
            1: "10.0.1.1",    # Gateway for 10.0.1.0/24
            2: "10.0.2.1",    # Gateway for 10.0.2.0/24
            3: "192.168.1.1"  # Gateway for 192.168.1.0/24
        }
        
        # Router port mapping for each subnet
        self.subnet_to_port = {
            "10.0.1.0/24": 1,
            "10.0.2.0/24": 2,
            "192.168.1.0/24": 3
        }
        
        # Track router ports (maps physical in_port -> logical port)
        self.router_port_map = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Log switch connection
        if datapath.id == 3:  # Router (s3)
            self.logger.info("Router s3 connected")
        else:  # Switches (s1, s2)
            self.logger.info(f"Switch s{datapath.id} connected")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                   priority=priority, match=match,
                                   instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=match, instructions=inst)
        datapath.send_msg(mod)

    def _get_subnet(self, ip):
        """Get the subnet prefix for an IP address"""
        return ip.rsplit('.', 1)[0] + '.0/24'

    def _is_same_subnet(self, ip1, ip2):
        """Check if two IPs are in the same subnet"""
        return ip1.rsplit('.', 1)[0] == ip2.rsplit('.', 1)[0]

    def _get_logical_port_for_ip(self, ip):
        """Get the logical port for a given IP address"""
        subnet = self._get_subnet(ip)
        return self.subnet_to_port.get(subnet)

    def _is_router_ip(self, ip):
        """Check if an IP belongs to the router"""
        return ip in self.port_to_ip.values()

    def _handle_arp(self, datapath, in_port, pkt):
        """Handle ARP packets"""
        arp_pkt = pkt.get_protocol(arp.arp)
        
        # Learn the ARP mapping
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        
        # Learn router port mapping if at router
        if datapath.id == 3:  # Router
            subnet = self._get_subnet(arp_pkt.src_ip)
            logical_port = self.subnet_to_port.get(subnet)
            if logical_port:
                self.router_port_map[in_port] = logical_port
            
        # Handle ARP request for router interface
        if datapath.id == 3 and arp_pkt.opcode == arp.ARP_REQUEST:
            if self._is_router_ip(arp_pkt.dst_ip):
                # Get the logical port for this IP
                for port, ip in self.port_to_ip.items():
                    if ip == arp_pkt.dst_ip:
                        # Create ARP reply
                        eth_pkt = pkt.get_protocol(ethernet.ethernet)
                        router_mac = self.port_to_mac[port]
                        
                        # Create packet
                        pkt_out = packet.Packet()
                        pkt_out.add_protocol(ethernet.ethernet(
                            dst=eth_pkt.src, src=router_mac, ethertype=ether_types.ETH_TYPE_ARP))
                        pkt_out.add_protocol(arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=router_mac, src_ip=arp_pkt.dst_ip,
                            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
                        pkt_out.serialize()
                        
                        # Send the reply
                        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                        out = datapath.ofproto_parser.OFPPacketOut(
                            datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                            in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, 
                            data=pkt_out.data)
                        datapath.send_msg(out)
                        self.logger.info(f"Sent ARP reply: {arp_pkt.dst_ip} is at {router_mac}")
                        return True
        return False

    def _handle_icmp_request_to_router(self, datapath, in_port, pkt):
        """Handle ICMP echo request to router interface"""
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        # Create echo reply packet
        pkt_out = packet.Packet()
        
        # Get router MAC for this interface
        for port, router_ip in self.port_to_ip.items():
            if router_ip == ip.dst:
                router_mac = self.port_to_mac[port]
                
                # Create reply packet
                pkt_out.add_protocol(ethernet.ethernet(
                    dst=eth.src, src=router_mac, ethertype=ether_types.ETH_TYPE_IP))
                pkt_out.add_protocol(ipv4.ipv4(
                    proto=1, src=ip.dst, dst=ip.src, ttl=64))
                pkt_out.add_protocol(icmp.icmp(
                    type_=icmp.ICMP_ECHO_REPLY, code=0, csum=0, data=icmp_pkt.data))
                pkt_out.serialize()
                
                # Send the reply
                actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, 
                    data=pkt_out.data)
                datapath.send_msg(out)
                return True
        return False

    def _should_block_by_policy(self, src_ip, dst_ip, proto):
        """Apply security policies"""
        src_subnet = self._get_subnet(src_ip)
        dst_subnet = self._get_subnet(dst_ip)
        
        # 1. Block pings from external to internal hosts
        if proto == 1 and src_subnet == "192.168.1.0/24":
            if dst_subnet.startswith("10."):  # Internal subnets
                self.logger.info(f"Blocked: ICMP from external {src_ip} to internal {dst_ip}")
                return True
                
        # 2. Block TCP/UDP between ext and ser
        if (proto == 6 or proto == 17):  # TCP or UDP
            is_ext = src_subnet == "192.168.1.0/24" or dst_subnet == "192.168.1.0/24"
            is_ser = src_ip == "10.0.2.2" or dst_ip == "10.0.2.2"
            if is_ext and is_ser:
                self.logger.info(f"Blocked: TCP/UDP between ext and ser: {src_ip} -> {dst_ip}")
                return True
                
        # 3. Block pings to gateways not in host's subnet
        if proto == 1 and self._is_router_ip(dst_ip):
            if not self._is_same_subnet(src_ip, dst_ip):
                self.logger.info(f"Blocked: Host {src_ip} pinging gateway {dst_ip} not in its subnet")
                return True
                
        return False  # Allow the packet

    def _handle_ip_at_router(self, datapath, in_port, pkt, buffer_id=None):
        """Handle IP packets at the router"""
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        
        # Check security policies
        if self._should_block_by_policy(ip.src, ip.dst, ip.proto):
            return True
            
        # Handle packets to router itself
        if self._is_router_ip(ip.dst):
            if ip.proto == 1:  # ICMP
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    return self._handle_icmp_request_to_router(datapath, in_port, pkt)
            return True
            
        # Get output port for destination IP
        dst_subnet = self._get_subnet(ip.dst)
        logical_port = self.subnet_to_port.get(dst_subnet)
        if not logical_port:
            self.logger.info(f"No route to subnet for {ip.dst}")
            return True
            
        # Find physical out port using router port mapping
        physical_out_port = None
        for phys_port, log_port in self.router_port_map.items():
            if log_port == logical_port:
                physical_out_port = phys_port
                break
                
        if not physical_out_port:
            self.logger.info(f"No physical port mapping for logical port {logical_port}")
            return True
            
        # Get destination MAC
        dst_mac = self.arp_table.get(ip.dst)
        if not dst_mac:
            self.logger.info(f"MAC for {ip.dst} unknown")
            return True
            
        # Check TTL
        if ip.ttl <= 1:
            self.logger.info(f"TTL expired for {ip.src} -> {ip.dst}")
            return True
            
        # Create router actions
        src_mac = self.port_to_mac[logical_port]
        actions = [
            datapath.ofproto_parser.OFPActionDecNwTtl(),
            datapath.ofproto_parser.OFPActionSetField(eth_src=src_mac),
            datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
            datapath.ofproto_parser.OFPActionOutput(physical_out_port)
        ]
        
        # Install flow rule
        match = datapath.ofproto_parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=ip.src, 
            ipv4_dst=ip.dst
        )
        
        self.add_flow(datapath, 1, match, actions, buffer_id=buffer_id)
        self.logger.info(f"Router: installed flow for {ip.src} -> {ip.dst} via port {physical_out_port}")
        
        # If no buffer_id, send packet out
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            # Create new packet with updated headers
            pkt_out = packet.Packet()
            pkt_out.add_protocol(ethernet.ethernet(
                dst=dst_mac, src=src_mac, ethertype=eth.ethertype))
            pkt_out.add_protocol(ipv4.ipv4(
                dst=ip.dst, src=ip.src, proto=ip.proto, ttl=ip.ttl-1))
                
            # Add upper layer protocols (TCP/UDP/ICMP)
            if ip.proto == 1:  # ICMP
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt:
                    pkt_out.add_protocol(icmp_pkt)
            elif ip.proto == 6:  # TCP
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    pkt_out.add_protocol(tcp_pkt)
            elif ip.proto == 17:  # UDP
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    pkt_out.add_protocol(udp_pkt)
                    
            pkt_out.serialize()
            
            # Send packet
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=pkt_out.data)
            datapath.send_msg(out)
            self.logger.info(f"Router: forwarded packet {ip.src} -> {ip.dst}")
            
        return True

    def _handle_switch_packet(self, datapath, in_port, pkt, buffer_id=None):
        """Handle packets at switches"""
        eth = pkt.get_protocol(ethernet.ethernet)
        dpid = datapath.id
        
        # Learn MAC address to avoid flooding next time
        dst_mac = eth.dst
        src_mac = eth.src
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port
        
        # If we know the destination port, use it; otherwise flood
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = datapath.ofproto.OFPP_FLOOD
            
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        
        # Install flow if not flooding
        if out_port != datapath.ofproto.OFPP_FLOOD:
            match = datapath.ofproto_parser.OFPMatch(eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions, buffer_id=buffer_id)
            
        # Send packet if no buffer_id
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=pkt.data)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        buffer_id = msg.buffer_id
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
            
        # Handle ARP packets
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            if self._handle_arp(datapath, in_port, pkt):
                return
                
        # Router logic (s3)
        if datapath.id == 3:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                if self._handle_ip_at_router(datapath, in_port, pkt, buffer_id):
                    return
        # Switch logic (s1, s2)
        else:
            self._handle_switch_packet(datapath, in_port, pkt, buffer_id)