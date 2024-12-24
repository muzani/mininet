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
        
        # Tambahkan switch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Tambahkan host
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')

        # Hubungkan host ke switch
        self.addLink(h1, s1, bw=10, delay='5ms')
        self.addLink(h2, s1, bw=10, delay='5ms')
        self.addLink(h3, s4, bw=10, delay='5ms')
        self.addLink(h4, s4, bw=10, delay='5ms')

        # Hubungkan switch ke switch
        self.addLink(s1, s2, bw=15, delay='2ms')
        self.addLink(s2, s3, bw=15, delay='2ms')
        self.addLink(s3, s4, bw=15, delay='2ms')
        self.addLink(s1, s4, bw=20, delay='1ms') 
        
topos = { 'mytopo': ( lambda: MyTopo() ) }

#sudo mn --custom sample-custom2.py --topo mytopo --switch ovsk --controller=remote
#sudo mn --custom single.py --topo mytopo
#secara default sudah ada controller
# xterm h1 h2 = untuk virtual terminal setiap host
# 