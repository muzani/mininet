from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def complex_topology():
    """Membuat topologi jaringan yang kompleks."""
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

    # Tambahkan controller
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

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
    net.addLink(s1, s4, bw=20, delay='1ms')  # Jalur alternatif dengan bandwidth lebih tinggi

    # Konfigurasi jaringan
    net.start()

    # Jalankan CLI untuk pengujian manual
    CLI(net)

    # Hentikan jaringan
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    complex_topology()
