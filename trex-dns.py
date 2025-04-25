from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from trex.stl.api import *
import itertools

class DNS64PerfTest:
    def __init__(self, duration=60, rate_pps=1000):
        self.duration = duration
        self.rate_pps = rate_pps
        self.octets = itertools.product(range(256), repeat=4)
        self.counter = 0



    def create_stream(self):
        # Use VM instructions to generate unique packets
        vm = STLVM()
        # Create the packet template
        l2 = Ether()
        l3 = IP(dst="192.168.0.195", src="192.168.0.60")
        l4 = UDP(dport=53, sport=1024)
        dns = DNS(rd=1, qd=DNSQR(qname="0000.dns64perf.test", qtype="AAAA"))
        base_pkt = l2 / l3 / l4/dns
        # Add instructions to modify the DNS query name dynamically
        vm.var(name="b", min_value="0.0.0.0", max_value="0.0.1.255", size=4, op="inc")
        #vm.var(name="c", min_value=0, max_value=255, size=1, op="inc")
        #vm.var(name="d", min_value=0, max_value=255, size=1, op="inc")

        # Build the dynamic DNS query name
        vm.write(
            fv_name="b",
            pkt_offset= len(base_pkt) - 24,
            byte_order= "big"
        )

        # Fix checksum for IP and UDP layers
        #vm.fix_chksum()
        vm.fix_chksum_hw(l3_offset=len(l2),l4_offset=len(l2)+len(l3),l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)

        
        return STLStream(
            packet=STLPktBuilder(pkt=base_pkt, vm=vm),
            mode=STLTXCont(pps=self.rate_pps),
            flow_stats=STLFlowStats(pg_id=1)
        )

    def run(self):
        c = STLClient()
        c.connect()
        c.reset(ports=[0])

        c.add_streams(self.create_stream(), ports=[0])

        c.clear_stats()
        c.start(ports=[0], duration=self.duration)
        c.wait_on_traffic(ports=[0])

        stats = c.get_stats(ports=[0])
        print(stats)
        sent = stats[0]['opackets']
        received = stats[0]['ipackets']  # RX port

        print(f"Sent packets: {sent}")
        print(f"Received packets: {received}")

        if received >= sent:
            print("✅ Zero loss confirmed!")
        else:
            print("❌ Packet loss detected!")

        c.disconnect()

if __name__ == "__main__":
    test = DNS64PerfTest(duration=1, rate_pps=50)
    test.run()