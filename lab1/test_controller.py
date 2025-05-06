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
        
        # MAC to port mapping for switches
        self.mac_to_port = {}
        
        # ARP table for IP-to-MAC mapping
        self.arp_table = {}
        
        # Define switch IDs
        self.SWITCH_1 = 1  # s1 (internal network)
        self.SWITCH_2 = 2  # s2 (server network)
        self.ROUTER = 3    # s3 (router)
        
        # Router port MACs
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",  # interface to s1 (internal)
            2: "00:00:00:00:01:02",  # interface to s2 (server)
            3: "00:00:00:00:01:03"   # interface to ext (external)
        }
        
        # Router port IPs
        self.port_to_own_ip = {
            1: "10.0.1.1",      # gateway for internal network
            2: "10.0.2.1",      # gateway for server network
            3: "192.168.1.1"    # gateway for external network
        }
        
        # Helper mappings
        self.ip_to_port = {ip: port for port, ip in self.port_to_own_ip.items()}
        
        # Subnet definitions
        self.subnets = {
            "10.0.1.0/24": 1,     # internal network
            "10.0.2.0/24": 2,     # server network
            "192.168.1.0/24": 3   # external network
        }
        
        # Port mappings for router interfaces
        self.router_port_mapping = {}
        
        # Known host MACs
        self.known_hosts = {}
        
        self.logger.info("Switch and Router controller initialized")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection and install table-miss flow entry"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry (lowest priority)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info(f"Switch {datapath.id} connected")
        
        # If this is the router, store the datapath
        if datapath.id == self.ROUTER:
            self.router_datapath = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """Add a flow entry to the switch's flow table"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                   priority=priority, match=match,
                                   instructions=inst, idle_timeout=idle_timeout,
                                   hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=match, instructions=inst,
                                   idle_timeout=idle_timeout,
                                   hard_timeout=hard_timeout)
        datapath.send_msg(mod)
    
    def is_ip_in_subnet(self, ip, subnet):
        """Check if an IP is in the given subnet (CIDR notation)"""
        network, prefix = subnet.split('/')
        prefix = int(prefix)
        
        # Convert IP and network to integers
        ip_int = self._ip_to_int(ip)
        network_int = self._ip_to_int(network)
        
        # Create a mask
        mask = (1 << 32) - (1 << (32 - prefix))
        
        # Check if IP is in subnet
        return (ip_int & mask) == (network_int & mask)
    
    def _ip_to_int(self, ip):
        """Convert IP address to integer"""
        octets = ip.split('.')
        return (int(octets[0]) << 24) + (int(octets[1]) << 16) + \
               (int(octets[2]) << 8) + int(octets[3])
    
    def _get_subnet_for_ip(self, ip):
        """Get the subnet for a given IP address"""
        for subnet in self.subnets:
            if self.is_ip_in_subnet(ip, subnet):
                return subnet
        return None
    
    def _handle_arp(self, datapath, in_port, pkt):
        """Handle ARP packets"""
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        
        # Get source and destination info
        src_mac = eth.src
        dst_mac = eth.dst
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
        
        # Learn source IP-to-MAC mapping
        self.arp_table[src_ip] = src_mac
        self.logger.info(f"ARP: Learned {src_ip} -> {src_mac}")
        
        # Map source MAC to a specific port for future routing
        logical_port = self._determine_logical_port(src_ip)
        if logical_port:
            self.known_hosts[src_mac] = {"ip": src_ip, "port": logical_port}
        
        # Learn router port mapping if this is the first packet from a host
        if datapath.id == self.ROUTER:
            subnet = self._get_subnet_for_ip(src_ip)
            if subnet:
                logical_port = self.subnets[subnet]
                if logical_port not in self.router_port_mapping.values():
                    self.router_port_mapping[in_port] = logical_port
                    self.logger.info(f"Learned router port mapping: {in_port} -> {logical_port}")
        
        # Handle ARP requests for router's gateway IPs
        if datapath.id == self.ROUTER and arp_pkt.opcode == arp.ARP_REQUEST:
            if dst_ip in self.port_to_own_ip.values():
                # This is asking for one of our router IPs
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                
                # Find port for this IP
                for port, ip in self.port_to_own_ip.items():
                    if ip == dst_ip:
                        router_mac = self.port_to_own_mac[port]
                        
                        # Create ARP reply
                        arp_reply = packet.Packet()
                        arp_reply.add_protocol(ethernet.ethernet(
                            ethertype=ether_types.ETH_TYPE_ARP,
                            dst=src_mac,
                            src=router_mac))
                        arp_reply.add_protocol(arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=router_mac,
                            src_ip=dst_ip,
                            dst_mac=src_mac,
                            dst_ip=src_ip))
                        
                        # Send the ARP reply
                        arp_reply.serialize()
                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(datapath=datapath,
                                              buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=ofproto.OFPP_CONTROLLER,
                                              actions=actions, data=arp_reply.data)
                        datapath.send_msg(out)
                        self.logger.info(f"Sent ARP reply: {dst_ip} -> {router_mac}")
                        return True
        
        return False  # Not handled specially
    
    def _determine_logical_port(self, ip):
        """Determine which logical router port an IP belongs to"""
        subnet = self._get_subnet_for_ip(ip)
        if subnet:
            return self.subnets[subnet]
        return None
    
    def _handle_icmp_at_router(self, datapath, in_port, pkt):
        """Apply ICMP security policies"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        if not ipv4_pkt or not icmp_pkt:
            return False
            
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        
        # Block ping from external to internal hosts
        src_subnet = self._get_subnet_for_ip(src_ip)
        dst_subnet = self._get_subnet_for_ip(dst_ip)
        
        if src_subnet == "192.168.1.0/24" and dst_subnet in ["10.0.1.0/24", "10.0.2.0/24"]:
            self.logger.info(f"Blocking ping from external {src_ip} to internal {dst_ip}")
            return True
            
        # Allow hosts to ping only their own gateway
        if dst_ip in self.port_to_own_ip.values():
            # This is a ping to a gateway IP
            dst_port = self.ip_to_port[dst_ip]
            is_own_gateway = False
            
            # Check if source is in same subnet as gateway
            for subnet, port in self.subnets.items():
                if port == dst_port and self.is_ip_in_subnet(src_ip, subnet):
                    is_own_gateway = True
                    break
                    
            if not is_own_gateway:
                self.logger.info(f"Blocking ping to gateway {dst_ip} from {src_ip}")
                return True
        
        return False  # Continue processing
    
    def _handle_tcp_udp_at_router(self, datapath, in_port, pkt):
        """Apply TCP/UDP security policies"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        if not ipv4_pkt or (not tcp_pkt and not udp_pkt):
            return False
            
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        
        # Block TCP/UDP between external host and server
        src_subnet = self._get_subnet_for_ip(src_ip)
        dst_subnet = self._get_subnet_for_ip(dst_ip)
        
        # External to server or server to external
        if ((src_subnet == "192.168.1.0/24" and dst_subnet == "10.0.2.0/24") or
            (src_subnet == "10.0.2.0/24" and dst_subnet == "192.168.1.0/24")):
            self.logger.info(f"Blocking TCP/UDP between {src_ip} and {dst_ip}")
            return True
        
        return False  # Continue processing
    
    def _handle_ipv4_at_router(self, datapath, in_port, pkt):
        """Handle routing of IPv4 packets"""
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if not ipv4_pkt:
            return False
            
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        
        # Apply protocol-specific policies
        if pkt.get_protocol(icmp.icmp):
            if self._handle_icmp_at_router(datapath, in_port, pkt):
                return True  # ICMP packet blocked
                
        if pkt.get_protocol(tcp.tcp) or pkt.get_protocol(udp.udp):
            if self._handle_tcp_udp_at_router(datapath, in_port, pkt):
                return True  # TCP/UDP packet blocked
        
        # Find destination subnet and port
        dst_subnet = self._get_subnet_for_ip(dst_ip)
        if not dst_subnet:
            self.logger.warning(f"No route found for {dst_ip}")
            return True  # Drop packet
            
        # Get logical port for destination subnet
        dst_logical_port = self.subnets[dst_subnet]
        
        # Find physical port from logical port
        out_port = None
        for phys_port, logical_port in self.router_port_mapping.items():
            if logical_port == dst_logical_port:
                out_port = phys_port
                break
                
        if not out_port:
            self.logger.warning(f"Physical port not found for logical port {dst_logical_port}")
            return True  # Drop packet
            
        # Get destination MAC from ARP table
        dst_mac = self.arp_table.get(dst_ip)
        if not dst_mac:
            self.logger.info(f"Destination MAC for {dst_ip} unknown, dropping")
            return True  # Drop packet
            
        # Get router MAC for outgoing interface
        router_mac = self.port_to_own_mac[dst_logical_port]
        
        # Create flow rule for this route
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=dst_ip
        )
        
        actions = [
            parser.OFPActionSetField(eth_src=router_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionDecNwTtl(),  # Decrease TTL
            parser.OFPActionOutput(out_port)
        ]
        
        # Install flow rule
        self.add_flow(datapath, 2, match, actions, idle_timeout=300)
        
        # Create a new packet for forwarding
        out_pkt = packet.Packet()
        
        # Add Ethernet header
        out_pkt.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype,
            dst=dst_mac,
            src=router_mac
        ))
        
        # Add IPv4 header with decremented TTL
        new_ttl = ipv4_pkt.ttl - 1
        if new_ttl <= 0:
            self.logger.info(f"Dropping packet with TTL=0: {src_ip} -> {dst_ip}")
            return True  # Drop packet with expired TTL
            
        out_pkt.add_protocol(ipv4.ipv4(
            dst=dst_ip,
            src=src_ip,
            proto=ipv4_pkt.proto,
            ttl=new_ttl
        ))
        
        # Add payload (TCP/UDP/ICMP)
        if pkt.get_protocol(tcp.tcp):
            out_pkt.add_protocol(pkt.get_protocol(tcp.tcp))
        elif pkt.get_protocol(udp.udp):
            out_pkt.add_protocol(pkt.get_protocol(udp.udp))
        elif pkt.get_protocol(icmp.icmp):
            out_pkt.add_protocol(pkt.get_protocol(icmp.icmp))
        
        # Serialize and send
        out_pkt.serialize()
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)],
            data=out_pkt.data
        )
        datapath.send_msg(out)
        
        self.logger.info(f"Routed packet {src_ip} -> {dst_ip} via port {out_port}")
        return True  # Packet handled
    
    def _learn_mac_port(self, datapath, src_mac, in_port):
        """Learn MAC to port mapping for switches"""
        dpid = datapath.id
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
            
        # Learn or update MAC-to-port mapping
        self.mac_to_port[dpid][src_mac] = in_port
        self.logger.debug(f"Learned MAC {src_mac} -> port {in_port} on switch {dpid}")
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle packet-in events"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Skip LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
            
        # Skip IPv6 packets
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        
        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        
        # Learn MAC to port mapping for all devices
        self._learn_mac_port(datapath, src_mac, in_port)
        
        # Handle ARP packets
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            if self._handle_arp(datapath, in_port, pkt):
                return  # ARP packet handled specially
        
        # Router processing
        if dpid == self.ROUTER:
            # Handle IPv4 packets with routing logic
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                if self._handle_ipv4_at_router(datapath, in_port, pkt):
                    return  # IPv4 packet handled by router
            
            # Other packets at router are dropped
            return
        
        # Switch logic for s1 and s2
        # Determine output port
        if dst_mac in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install flow for known unicast destination
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst_mac)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=300)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=300)
        
        # Forward packet
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)
        
        # Log forwarding
        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info(f"Switch {dpid}: {src_mac} -> {dst_mac} via port {out_port}")
        else:
            self.logger.info(f"Switch {dpid}: flooding packet from {src_mac}")