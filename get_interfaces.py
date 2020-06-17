from scapy.all import get_if_list

def avalible_interfaces():
    interfaces = get_if_list()
    return interfaces