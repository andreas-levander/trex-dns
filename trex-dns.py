from scapy.all import DNS, DNSQR, IP, UDP, Ether
from trex.stl.api import *
import math
import argparse
import datetime
import configparser

class DNS64PerfTest:
    def __init__(self, duration=60, rate_pps=1000, ip_dst="", ip_src=""):
        self.duration = duration
        self.rate_pps = rate_pps
        self.ip_dst = ip_dst
        self.ip_src = ip_src


    def create_stream(self):
        #print(f"IP src: {self.ip_src}, IP dst: {self.ip_dst}")
        # Use VM instructions to generate unique packets
        vm = STLVM()
        # Create the packet template
        l2 = Ether()
        l3 = IP(dst=self.ip_dst, src=self.ip_src)
        
        l4 = UDP(dport=53, sport=1024)
        dns = DNS(rd=0, qd=DNSQR(qname="0000.dns64perf.test", qtype="AAAA"))
        base_pkt = l2/ l3 / l4 / dns
        # Add instructions to modify the DNS query name dynamically
        vm.var(name="b", min_value="0.0.0.0", max_value="4.0.0.0", size=4, op="inc")
        vm.var(name="c", min_value=1024, max_value=10000, size=2, op="inc")
        #vm.var(name="d", min_value=0, max_value=255, size=1, op="inc")

        # Build the dynamic DNS query name
        vm.write(
            fv_name="b",
            pkt_offset= len(base_pkt) - 24,
            byte_order= "little"
        )
        
        vm.write(
            fv_name="c",
            pkt_offset= "UDP.sport",
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
        #print(stats)
        sent = stats[0]['opackets']
        received = stats[0]['ipackets']  # RX port

        print(f"Sent packets: {sent}")
        print(f"Received packets: {received}")

        if received >= sent:
            print("✅ Zero loss confirmed!")
        else:
            print("❌ Packet loss detected!")

        c.disconnect()
        return (sent, received)

def binary_searchQPS(low, high, duration, accuracy, ip_src, ip_dst):
    print(f"Minimum QPS: {low}, Maximum QPS: {high}, Duration: {duration} seconds, Accuracy: {accuracy}")

    while low < high:
        mid = low + math.ceil((high - low) / 2)
        if high - low < accuracy:
            break
        print(f"Starting test QPS: {mid:,}, Requests: {mid * duration:,}")
        test = DNS64PerfTest(duration=duration, rate_pps=mid, ip_dst=ip_dst, ip_src=ip_src)
        
        q, a = test.run()
        print(f"QPS: {mid:,},  Queries: {q:,}, Answers: {a:,}\n")
        if q > a:
            high = mid
        else:
            low = mid
       
    return low

def write_csv(filename, data):
    with open(filename, 'a') as f:
        f.write(f"{data['run']},{data['qps']}\n")

def get_args():
    parser = argparse.ArgumentParser(
                    prog='DNS TREX binary search',
                    description='Search for the maximum QPS for a given zone file',
                    epilog='2025 Andreas Levander')
    
    parser.add_argument('-f', '--file', help='config file name', required=False, default='config.cfg')

    return parser.parse_args().file

def main():
    cnfg_file = get_args()
    config = configparser.ConfigParser()
    files = config.read(cnfg_file)
    if not files:
        raise Exception(f"Could not read config file {cnfg_file}")

    min_qps = config.getint('DEFAULT', 'min_qps')
    max_qps = config.getint('DEFAULT', 'max_qps')
    duration = config.getint('DEFAULT', 'duration')
    accuracy = config.getint('DEFAULT', 'accuracy')
    runs = config.getint('DEFAULT', 'runs')
    ip_src = config.get('DEFAULT', 'ip_src')
    ip_dst = config.get('DEFAULT', 'ip_dst')


    print("Starting DNS performance test...")
    before = datetime.datetime.now()

    for run in range(1, runs + 1):
        rt = datetime.datetime.now()
        print("\n********************************")
        print(f"Starting run {run}")
        log_target = f"runs.csv"
        res = binary_searchQPS(min_qps, max_qps, duration, accuracy, ip_src, ip_dst)
        write_csv(log_target, {'run': run, 'qps': res})
        print(f"Run {run} done in {datetime.datetime.now() - rt}")
    
    after = datetime.datetime.now()
    print(f"Total time taken: {after - before} for {runs} runs")
    

if __name__ == "__main__":
    #test = DNS64PerfTest(rate_pps=5, duration=1, ip_dst="192.168.0.196", ip_src="192.168.0.60")
    #test.run()
    main()