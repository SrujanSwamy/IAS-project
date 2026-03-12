#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class ProjectTopo( Topo ):
    """
    Custom Topology for SDN Anomaly Detection Project.
    h1, h2: Normal users
    h3: Attacker
    h4: Victim Server
    """
    def build( self ):
        # Add a single Open vSwitch
        s1 = self.addSwitch( 's1', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        # Add hosts with static IPs and MACs for easier tracking during detection
        h1 = self.addHost( 'h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01' ) # Normal user
        h2 = self.addHost( 'h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02' ) # Normal user
        h3 = self.addHost( 'h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03' ) # Attacker
        h4 = self.addHost( 'h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04' ) # Victim

        # Connect hosts to the switch
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1 )
        self.addLink( h4, s1 )

def run():
    setLogLevel( 'info' )
    info( '*** Creating network\n' )
    topo = ProjectTopo()
    
    # Initialize the network without auto-adding a controller
    net = Mininet( topo=topo, controller=None, switch=OVSKernelSwitch )
    
    # Add the remote Ryu controller running on localhost, standard OpenFlow port 6653
    c0 = net.addController( 'c0', controller=RemoteController, ip='127.0.0.1', port=6653 )
    
    info( '*** Starting network\n' )
    net.start()
    
    info( '*** Running CLI\n' )
    CLI( net )
    
    info( '*** Stopping network\n' )
    net.stop()

if __name__ == '__main__':
    run()