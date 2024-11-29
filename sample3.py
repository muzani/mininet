from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel

class MyTopo( Topo ):
    "Simple topology example."
	
	def myNetwork():
    # Create an instance of Mininet class i.e. the network with default values
    net = Mininet(controller=RemoteController)

    #info( '*** Adding controller\n' )
    c0 = net.addController('c0', cls=RemoteController)
    #hc = net.addHost( 'hc', ip='127.0.0.1' )
    info( '*** Adding switches\n')
    s1 = net.addSwitch('s1')
    s5 = net.addSwitch('s5')
    s2 = net.addSwitch('s2')
    info( '*** Adding links\n')
    #net.addLink(hc, s1)
    net.addLink(s1, s5, cls=TCLink)
    net.addLink(s5, s2, cls=TCLink)

    hosts = list()
    #  add all remaining hosts to s2
    info( '*** Adding hosts and Links\n')

    for i in range (1,11):
        name = 'h'+str(i)
        host = net.addHost(name)
        net.addLink( s2, host, cls=TCLink)
        hosts.append(host)

    info( '*** Starting network\n')
    net.start()
    #hc.cmdPrint('ryu-manager ryu/simple_switch_13.py \
    #            --verbose 1> tmp/controller-ryu.log 2>&1 &')
    # Start the Mininet CLI to run commands
    CLI(net)
    # Stop the network
    net.stop()

if __name__ == '__main__':
    from mininet.log import setLogLevel, info
    from mininet.net import Mininet
    from mininet.link import TCLink
    from mininet.cli import CLI
    from mininet.node import RemoteController

    setLogLevel( 'info' )
    myNetwork()