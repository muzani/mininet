from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def complex_topology():
    """Membuat topologi jaringan yang kompleks dengan koneksi yang valid."""
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

    # Tambahkan controller
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Tambahkan switch
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')

    # Tambahkan host
    h1 = net.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
    h2 = net.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
    h3 = net.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254')
    h4 = net.addHost('h4', ip='10.0.0.4/24', defaultRoute='via 10.0.0.254')

    # Hubungkan host ke switch
    net.addLink(h1, s1, bw=10, delay='5ms')
    net.addLink(h2, s2, bw=10, delay='5ms')
    net.addLink(h3, s3, bw=10, delay='5ms')
    net.addLink(h4, s4, bw=10, delay='5ms')

    # Hubungkan switch ke switch
    net.addLink(s1, s2, bw=15, delay='2ms')
    net.addLink(s2, s3, bw=15, delay='2ms')
    net.addLink(s3, s4, bw=15, delay='2ms')
    net.addLink(s4, s1, bw=15, delay='2ms')  # Jalur alternatif untuk konektivitas penuh

    # Konfigurasi jaringan
    net.start()

    # Pastikan semua switch terhubung ke controller
    for switch in [s1, s2, s3, s4]:
        switch.cmd('ovs-vsctl set-controller %s tcp:127.0.0.1:6633' % switch.name)

    # Uji koneksi antar host
    net.pingAll()

    # Jalankan CLI untuk pengujian manual
    CLI(net)

    # Hentikan jaringan
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    complex_topology()
