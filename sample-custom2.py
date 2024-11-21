"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.log import setLogLevel

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        
        #add Switchs
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )

        # Add links between host and switchs
        self.addLink( s1, h1 )
        self.addLink( s2, h2 )
        self.addLink( s3, h3 )
        
        # Add link between switchs
        self.addLink( s1, s2 )
        self.addLink( s2, s3 )
        
if __name__ == '__main__':
    # Set Mininet log level
    setLogLevel('info')

topos = { 'mytopo': ( lambda: MyTopo() ) }

#sudo mn --custom sample-custom2.py --topo mytopo --switch ovsk --controller=remote
