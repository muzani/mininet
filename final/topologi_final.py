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

        # Add hosts
        # h1 = self.addHost( 'h1' )
        # h2 = self.addHost( 'h2' )
        # h3 = self.addHost( 'h3' )
        
        h1 = self.addHost( 'h1' ,ip='192.168.1.1')
        h2 = self.addHost( 'h2' ,ip='192.168.1.2')
        h3 = self.addHost( 'h3' ,ip='192.168.1.3')
        h4 = self.addHost( 'h4' ,ip='192.168.1.4')
        h5 = self.addHost( 'h5' ,ip='192.168.1.5')
        h6 = self.addHost( 'h6' ,ip='192.168.1.6')
        
        #add Switchs
        s1 = self.addSwitch( 's1') #, cls=OVSBridge
        s2 = self.addSwitch( 's2')
        s3 = self.addSwitch( 's3')
        s4 = self.addSwitch( 's4')

        # Add links between host and switchs
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1 )        
        self.addLink( h4, s2 )
        self.addLink( h5, s3 )
        self.addLink( h6, s4 )
        
        # Add link between switchs
        self.addLink( s1, s2 )
        self.addLink( s2, s3 )
        self.addLink( s4, s1 )
        
topos = { 'mytopo': ( lambda: MyTopo() ) }

#sudo mn --custom sample-custom2.py --topo mytopo --switch ovsk --controller=remote
#sudo mn --custom single.py --topo mytopo
#secara default sudah ada controller
# xterm h1 h2 = untuk virtual terminal setiap host
# 