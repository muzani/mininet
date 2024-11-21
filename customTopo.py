
from mininet.topo import Topo

class MyTopo(topo):
    "simple topology example"
    
    def build(self):
        "create custom topo"
        #add hostas and switchs
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        
        #add links
        self.addLink(s1,s2)
        self.addLink(s1,h1)
        self.addLink(s2,h2)

topos = {'mytopo': ( lambda: MyTopo())}
        
        
        