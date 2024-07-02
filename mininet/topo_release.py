#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.nodelib import NAT
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='192.168.206.179',
                      port=6653,
                      protocol='tcp')

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='0000000000000001')

    info( '*** Add hosts\n')
    natIP = '10.0.0.5'
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute= 'via ' + natIP)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute= 'via ' + natIP)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute= 'via ' + natIP)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute= 'via ' + natIP)
    nat = net.addHost('nat', cls=NAT, ip=natIP, inNamespace=False)

    info( '*** Add links\n')
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s1, h3)
    net.addLink(s1, h4)
    net.addLink(s1, nat)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])

    info( '*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

if __name__=='__main__':
    setLogLevel('info')
    myNetwork()