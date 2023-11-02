from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.topo import Topo

#uvjhu
class CustomTopology(Topo):
    def __init__(self):
        Topo.__init__(self)
        # Add 2 switches to the topology
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')

        # Add 4 hosts to the topology
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')
        host5 = self.addHost('h5')

        # Connect hosts to switches
        self.addLink(host1, switch1)
        self.addLink(host2, switch1)
        self.addLink(host3, switch1)
        self.addLink(host4, switch2)
        self.addLink(host5, switch2)

        # Connect switches together
        self.addLink(switch1, switch2)
        

# Create Mininet network with the custom topology
if __name__=="__main__":
    topo=CustomTopology()
    net=Mininet(topo)
    net.start()
