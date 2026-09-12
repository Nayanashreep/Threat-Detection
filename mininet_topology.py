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

from mininet.clean import cleanup
from mininet.node import RemoteController, OVSKernelSwitch
import socket

def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0

def run():
    # Clean up any leftover virtual interfaces from previous runs
    info('*** Cleaning up leftover interfaces...\n')
    cleanup()
    
    topo = FinancialNetworkTopo()
    
    # If Ryu or remote controller is active on 6633/6653 use it; otherwise use native OVS OpenFlow
    if is_port_open(6633) or is_port_open(6653):
        ctrl = RemoteController
        info('*** Using Active Remote SDN Controller (127.0.0.1)\n')
        net = Mininet(topo=topo, controller=ctrl, switch=OVSKernelSwitch, autoSetMacs=True)
    else:
        info('*** Using Native Open vSwitch OpenFlow Engine\n')
        net = Mininet(topo=topo, controller=None, switch=OVSKernelSwitch, autoSetMacs=True)

    info('*** Starting network\n')
    net.start()

    # If running in standalone OVS mode, configure normal forwarding rules
    if not is_port_open(6633) and not is_port_open(6653):
        for sw in net.switches:
            sw.cmd(f'ovs-vsctl set-fail-mode {sw.name} standalone')
            sw.cmd(f'ovs-ofctl add-flow {sw.name} actions=NORMAL')

    info('\n*** Simulated Financial Network Active ***\n')
    info('Hosts:\n')
    info('  h1 : Customer (10.0.0.1)\n')
    info('  h2 : Bank Server (10.0.0.2)\n')
    info('  h3 : Payment Gateway (10.0.0.3)\n')
    info('  h4 : Attacker (10.0.0.4)\n')
    info('  h5 : Honeypot (10.0.0.5)\n')
    
    # Automatically start honeypot service inside h5 and bank service on h2
    h5 = net.get('h5')
    h2 = net.get('h2')
    base_dir = os.path.dirname(os.path.abspath(__file__))
    honeypot_script = os.path.join(base_dir, 'honeypot.py')
    
    info('*** Launching Honeypot on h5 (10.0.0.5:8000)...\n')
    h5.cmd(f'python3 {honeypot_script} 8000 > /tmp/honeypot_h5.log 2>&1 &')
    
    info('*** Launching Bank API on h2 (10.0.0.2:8855)...\n')
    h2.cmd('python3 -m http.server 8855 > /tmp/bank_h2.log 2>&1 &')

    info('\n*** Useful Commands:\n')
    info('  h1 ping -c 3 h2           # Normal customer traffic to Bank\n')
    info('  h4 nc -nv 10.0.0.5 8000   # Attacker probe to Honeypot\n')
    info('  h1 curl http://10.0.0.2:8855   # Customer querying Bank API\n')
    
    CLI(net)
    
    info('*** Stopping background host services...\n')
    h5.cmd('pkill -f honeypot.py')
    h2.cmd('pkill -f http.server')
    
    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()


