"""
topology.py — Mininet topology for SDN Packet Logger
=====================================================
Creates a 3-host, 1-switch star topology.
Hosts: h1 (10.0.0.1), h2 (10.0.0.2), h3 (10.0.0.3)
Switch: s1 (OpenFlow 1.3) → Ryu controller at 127.0.0.1:6653

Run AFTER starting the Ryu controller:
  sudo python topology.py

Built-in test scenarios (type in Mininet CLI):
  Scenario A — Normal forwarding:
    mininet> h1 ping -c 4 h2

  Scenario B — Blocked flow (firewall):
    mininet> h1 ping -c 4 h3    ← blocked if rule added in controller

  Scenario C — Throughput test (iperf):
    mininet> iperf h1 h2

  Scenario D — Port scan simulation:
    mininet> h1 nmap -p 1-100 10.0.0.2    (requires nmap installed)

  Check flow tables:
    mininet> sh ovs-ofctl dump-flows s1
"""

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink


def create_topology():
    net = Mininet(
        switch     = OVSKernelSwitch,
        controller = RemoteController,
        link       = TCLink,           # allows bandwidth/delay params
        autoSetMacs = True,
    )

    # Remote Ryu controller
    c0 = net.addController("c0", ip="127.0.0.1", port=6653)

    # OpenFlow 1.3 switch
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    # Three hosts
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
   

    # Links with 10 Mbps bandwidth and 2ms delay (realistic LAN sim)
    net.addLink(h1, s1, bw=10, delay="2ms")
    net.addLink(h2, s1, bw=10, delay="2ms")
    net.addLink(h3, s1, bw=10, delay="2ms")


    net.start()

    print("\n" + "="*60)
    print("  SDN Packet Logger — Mininet Topology Started")
    print("="*60)
    print("  Hosts:  h1=10.0.0.1  h2=10.0.0.2  h3=10.0.0.3")
    print("  Switch: s1 (OpenFlow 1.3)")
    print("  Controller: Ryu on 127.0.0.1:6653")
    print("  Dashboard:  http://localhost:5001")
    print("="*60)
    print("\n  Test commands:")
    print("    h1 ping -c 4 h2          # normal forwarding")
    print("    h1 ping -c 4 h3          # test firewall rule")
    print("    iperf h1 h2              # throughput test")
    print("    sh ovs-ofctl dump-flows s1   # view flow table")
    print("    sh ovs-ofctl dump-ports  s1  # view port stats")
    print()

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_topology()
