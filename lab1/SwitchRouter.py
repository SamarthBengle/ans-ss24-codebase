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
        
        # MAC to port mapping
        self.mac_to_port = {}
        
        # ARP table for IP-to-MAC mapping
        self.arp_table = {}
        
        # Define switch IDs
        self.SWITCH_1 = 1  # Internal network switch
        self.SWITCH_2 = 2  # Server network switch
        self.ROUTER = 3    # Router implemented as a switch
        
        # Define router MAC addresses (from network diagram)
        self.router_macs = {
            "internal": "00:00:00:00:01:01",  # Interface to internal network (s1)
            "server": "00:00:00:00:01:02",    # Interface to server network (s2)
            "external": "00:00:00:00:01:03"   # Interface to external network
        }
        
        # Router interface IP addresses
        self.router_ips = {
            "internal": "10.0.1.1",     # Gateway for internal network
            "server": "10.0.2.1",       # Gateway for server network
            "external": "192.168.1.1"   # Gateway for external network
        }
        
        # Network subnets
        self.subnets = {
            "10.0.1.0/24": "internal",   # Internal network
            "10.0.2.0/24": "server",     # Server network
            "192.168.1.0/24": "external" # External network
        }
        
        # Router port mapping (physical port -> network type)
        # Based on the logs - these need to match your actual network!
        self.router_ports = {
            1: "external",   # Port 1 connects to external network (ext)
            2: "internal",   # Port 2 connects to internal network (s1)
            3: "server"      # Port 3 connects to server network (s2)
        }
        
        # Known host IPs and their networks
        self.host_ips = {
            "10.0.1.2": "internal",    # h1
            "10.0.1.3": "internal",    # h2
            "10.0.2.2": "server",      # ser
            "192.168.1.123": "external"  # ext
        }
        
        self.logger.info("Router controller initialized")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection and install table-miss flow entry"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info(f"Switch {datapath.id} connected")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """Add a flow entry to the switch's flow table"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
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
        ip_int = sum([int(octet) << (24 - 8 * i) for i, octet in enumerate(ip.split('.'))])
        network_int = sum([int(octet) << (24 - 8 * i) for i, octet in enumerate(network.split('.'))])
        
        # Create a mask
        mask = (1 << 32) - (1 << (32 - prefix))
        
        # Check if IP is in subnet
        return (ip_int & mask) == (network_int & mask)
    
    def get_subnet_for_ip(self, ip):
        """Get the subnet for a given IP address"""
        for subnet in self.subnets:
            if self.is_ip_in_subnet(ip, subnet):
                return subnet
        return None
    
    def get_network_for_ip(self, ip):
        """Get the network type (internal/server/external) for an IP"""
        if ip in self.host_ips:
            return self.host_ips[ip]
            
        subnet = self.get_subnet_for_ip(ip)
        if subnet:
            return self.subnets[subnet]
        return None
    
    def should_block_traffic(self, src_ip, dst_ip):
        """Determine if traffic should be blocked based on security policy"""
        src_net = self.get_network_for_ip(src_ip)
        dst_net = self.get_network_for_ip(dst_ip)
        
        # Block traffic between external and internal/server networks
        if src_net == "external" and dst_net in ["internal", "server"]:
            return True
        if dst_net == "external" and src_net in ["internal", "server"]:
            return True
            
        return False
    
    def handle_arp(self, datapath, in_port, pkt):
        """Handle ARP packets"""
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        
        # Get source info
        src_mac = eth.src
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
        
        # Learn IP-to-MAC mapping
        self.arp_table[src_ip] = src_mac
        self.logger.info(f"Learned ARP mapping: {src_ip} -> {src_mac}")
        
        # Check if this is an ARP request for one of our gateway IPs
        if arp_pkt.opcode == arp.ARP_REQUEST and dst_ip in self.router_ips.values():
            # Find which network this request is for
            net_type = None
            for net, ip in self.router_ips.items():
                if ip == dst_ip:
                    net_type = net
                    break
                    
            if net_type:
                # Get MAC for this gateway
                router_mac = self.router_macs[net_type]
                
                # Create ARP reply
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                
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
                
                # Send the reply
                arp_reply.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions, data=arp_reply.data)
                datapath.send_msg(out)
                self.logger.info(f"Sent ARP reply: {dst_ip} ({net_type}) -> {router_mac}")
                return True
        
        return False
    
    def handle_ipv4(self, datapath, in_port, pkt):
        """Handle IPv4 packets at the router"""
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if not ipv4_pkt:
            return False
            
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        
        # Check security policies
        if self.should_block_traffic(src_ip, dst_ip):
            self.logger.info(f"Blocking traffic: {src_ip} -> {dst_ip}")
            return True
        
        # Get source and destination networks
        src_net = self.get_network_for_ip(src_ip)
        dst_net = self.get_network_for_ip(dst_ip)
        
        if not dst_net:
            self.logger.info(f"Unknown destination network for {dst_ip}")
            return False
        
        self.logger.info(f"Routing from {src_net} to {dst_net}: {src_ip} -> {dst_ip}")
        
        # Find outgoing port
        out_port = None
        for port, net in self.router_ports.items():
            if net == dst_net:
                out_port = port
                break
                
        if not out_port:
            self.logger.info(f"No outgoing port for network {dst_net}")
            return False
            
        # Get destination MAC
        dst_mac = self.arp_table.get(dst_ip)
        
        # If we don't know the MAC, flood the packet
        if not dst_mac:
            self.logger.info(f"Unknown MAC for {dst_ip}, using broadcast")
            dst_mac = "ff:ff:ff:ff:ff:ff"
        
        # Get router MAC for outgoing interface
        router_mac = self.router_macs[dst_net]
        
        # Create actions for packet_out
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        actions = [
            parser.OFPActionSetField(eth_src=router_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionDecNwTtl(),  # Decrease TTL
            parser.OFPActionOutput(out_port)
        ]
        
        # Send the packet out
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)
        
        self.logger.info(f"Routed packet: {src_ip} -> {dst_ip} via port {out_port}")
        return True
    
    def learn_mac_port(self, datapath, src_mac, in_port):
        """Learn MAC to port mapping"""
        dpid = datapath.id
        
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
            
        self.mac_to_port[dpid][src_mac] = in_port
    
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
        
        self.logger.debug(f"Packet in switch {dpid}, port {in_port}, src {src_mac}, dst {dst_mac}")
        
        # Learn MAC-to-port mapping for all switches
        self.learn_mac_port(datapath, src_mac, in_port)
        
        # Handle ARP packets
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # Learn the ARP mapping for all switches
            arp_pkt = pkt.get_protocol(arp.arp)
            self.arp_table[arp_pkt.src_ip] = src_mac
            
            # For the router, handle ARP specially
            if dpid == self.ROUTER:
                if self.handle_arp(datapath, in_port, pkt):
                    return
        
        # At the router, handle IPv4 routing
        if dpid == self.ROUTER and eth.ethertype == ether_types.ETH_TYPE_IP:
            if self.handle_ipv4(datapath, in_port, pkt):
                return
        
        # For normal switches, handle standard switching
        if dpid in [self.SWITCH_1, self.SWITCH_2]:
            # Check if we know the destination MAC
            if dst_mac in self.mac_to_port.get(dpid, {}):
                out_port = self.mac_to_port[dpid][dst_mac]
                self.logger.debug(f"Forwarding to known MAC {dst_mac} on port {out_port}")
            else:
                # Flood for broadcast or unknown destination
                out_port = ofproto.OFPP_FLOOD
                self.logger.debug(f"Flooding packet from {src_mac} (unknown dst {dst_mac})")
            
            # Send packet out
            actions = [parser.OFPActionOutput(out_port)]
            
            # Install a flow for known unicast destinations
            if dst_mac != "ff:ff:ff:ff:ff:ff" and out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_dst=dst_mac)
                self.add_flow(datapath, 1, match, actions, idle_timeout=300)
            
            # Send the packet out
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER else ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)