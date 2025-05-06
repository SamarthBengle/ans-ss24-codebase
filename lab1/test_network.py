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

#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):
    """Network Topology for Advanced Networked Systems Lab1"""

    def __init__(self):
        # Initialize the topology
        Topo.__init__(self)

        # Add hosts with their IP addresses and default gateways
        h1 = self.addHost('h1', ip="10.0.1.2/24", mac="00:00:00:00:00:01", defaultRoute="via 10.0.1.1")
        h2 = self.addHost('h2', ip="10.0.1.3/24", mac="00:00:00:00:00:02", defaultRoute="via 10.0.1.1")
        ext = self.addHost('ext', ip="192.168.1.123/24", mac="00:00:00:00:00:04", defaultRoute="via 192.168.1.1")
        ser = self.addHost('ser', ip="10.0.2.2/24", mac="00:00:00:00:00:03", defaultRoute="via 10.0.2.1")

        # Add switches (s1, s2) and router (s3)
        s1 = self.addSwitch('s1', dpid='1')  # Internal network switch
        s2 = self.addSwitch('s2', dpid='2')  # Server network switch
        router = self.addSwitch('s3', dpid='3')  # Router (implemented as a switch)

        # Add links with bandwidth and delay parameters
        # Internal network links
        self.addLink(s1, h1, bw=15, delay='10ms')
        self.addLink(s1, h2, bw=15, delay='10ms')
        
        # Server network link
        self.addLink(ser, s2, bw=15, delay='10ms')
        
        # Router links WITH IP configuration (critical for ARP to work properly)
        self.addLink(router, ext, intfName2='s3-ext', params2={'ip': '192.168.1.1/24'}, bw=15, delay='10ms')
        self.addLink(s1, router, intfName2='s3-eth3', params2={'ip': '10.0.1.1/24'}, bw=15, delay='10ms')
        self.addLink(s2, router, intfName2='s3-eth2', params2={'ip': '10.0.2.1/24'}, bw=15, delay='10ms')


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1', 
        controller=RemoteController, 
        ip="127.0.0.1", 
        port=6653)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    # Set log level
    setLogLevel('info')
    # Run the network
    run()