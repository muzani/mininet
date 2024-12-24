"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel
from mininet.node import OVSBridge

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."
        net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

        # Tambahkan switch
        s1 = net.addSwitch('s1')
        s2 = net.addSwitch('s2')
        s3 = net.addSwitch('s3')
        s4 = net.addSwitch('s4')

        # Tambahkan host
        h1 = net.addHost('h1', ip='10.0.0.1/24')
        h2 = net.addHost('h2', ip='10.0.0.2/24')
        h3 = net.addHost('h3', ip='10.0.0.3/24')
        h4 = net.addHost('h4', ip='10.0.0.4/24')

        # Hubungkan host ke switch
        net.addLink(h1, s1, bw=10, delay='5ms')
        net.addLink(h2, s1, bw=10, delay='5ms')
        net.addLink(h3, s4, bw=10, delay='5ms')
        net.addLink(h4, s4, bw=10, delay='5ms')

        # Hubungkan switch ke switch
        net.addLink(s1, s2, bw=15, delay='2ms')
        net.addLink(s2, s3, bw=15, delay='2ms')
        net.addLink(s3, s4, bw=15, delay='2ms')
        net.addLink(s1, s4, bw=20, delay='1ms') 
        
topos = { 'mytopo': ( lambda: MyTopo() ) }

#sudo mn --custom sample-custom2.py --topo mytopo --switch ovsk --controller=remote
#sudo mn --custom single.py --topo mytopo
#secara default sudah ada controller
# xterm h1 h2 = untuk virtual terminal setiap host
# 