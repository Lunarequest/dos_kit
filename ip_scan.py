from scapy.all import *

def ipscan(network_range, interface):
    x = network_range.split("/")
    ip = x[0]
    ip_range = x[1]
    ip_adress = []
    up_ips = []
    st_bits = ip.split('.')[3:4][0]
    for i in range(0,int(ip_range)+1):
        eval_ip = ".".join(ip.split('.'[:-1]))+'.'+str(i)
        ip_adress.append(eval_ip)
    
    for ip in ip_adress:
        ptk = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans,unans = srp(ptk,iface=interface,timeout=0.1, verbose=False)
        for snt, revc in ans:
            if revc:
                up_ips.append(ip)

    return up_ips