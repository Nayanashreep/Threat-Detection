#!/usr/bin/python
"""
SDN-Based Financial Network Topology for Mininet
Provides a simulated network with:
- Customer (Host 1)
- Bank Server (Host 2)
- Payment Gateway (Host 3)
- Attacker (Host 4)
- Honeypot (Host 5)

Run this on a system with Mininet installed (usually requires root):
  sudo python mininet_topology.py
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import os

class FinancialNetworkTopo(Topo):
    def build(self):
        # Add exactly 2 switches as requested in the architecture
        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')

        # Add hosts
        customer = self.addHost('h1', ip='10.0.0.1')
        bank_server = self.addHost('h2', ip='10.0.0.2')
        payment_gw = self.addHost('h3', ip='10.0.0.3')
        attacker = self.addHost('h4', ip='10.0.0.4')
        honeypot = self.addHost('h5', ip='10.0.0.5')

        # Connect hosts to S1
        self.addLink(customer, s1)     # h1 -> s1
        self.addLink(attacker, s1)     # h4 -> s1
        self.addLink(honeypot, s1)     # h5 -> s1

        # Connect hosts to S2
        self.addLink(bank_server, s2)  # h2 -> s2
        self.addLink(payment_gw, s2)   # h3 -> s2

        # Connect S1 and S2 together
        self.addLink(s1, s2)

def run():
    topo = FinancialNetworkTopo()
    # Using a generic remote controller to represent the SDN logic
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSKernelSwitch)
    
    info('*** Starting network\n')
    net.start()

    info('\n*** Simulated Financial Network Active ***\n')
    info('Hosts:\n')
    info('  h1 : Customer (10.0.0.1)\n')
    info('  h2 : Bank Server (10.0.0.2)\n')
    info('  h3 : Payment Gateway (10.0.0.3)\n')
    info('  h4 : Attacker (10.0.0.4)\n')
    info('  h5 : Honeypot (10.0.0.5)\n')
    
    info('\n*** Useful Commands:\n')
    info('  h1 ping h2          # Normal customer traffic to Bank\n')
    info('  h4 nc h5 8000       # Attacker hitting the honeypot\n')
    
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
