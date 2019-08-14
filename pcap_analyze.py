import argparse
from enum import Enum
import os
import sys
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import time

class PktDirection(Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2

def printable_timestamp(ts,resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_se_str = time.strftime('%Y-%m-%d %H:%M:%s', time.localtime(ts_sec))
    return  ('%s.%s' %(ts_se_str,ts_subsec))

def process_pcap(file_name ,srv ,cli):
    print ('Opening {} ...'.format(file_name))
    count = 0
    interesting_packet_count = 0

    (server_ip, server_port) = srv.split(':')
    (client_ip, client_port) = cli.split(':')

    for (pkd_data, pkt_metadata) in RawPcapReader(file_name):

        count +=1
        ether_pkt = Ether(pkd_data)
        if 'type' not in ether_pkt.fields:
            ## LLC frame will have  `len`  instead of `none`
            continue
        if ether_pkt.type != 0x800:
            #designate non ipv4 packages
            continue
        ip_pkt = ether_pkt[IP]
        if ip_pkt.proto != 6:
            # non tcp package
            continue

        direction = PktDirection.not_defined

        if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
            # Uninteresting source IP address
            continue

        if (ip_pkt.dst != server_ip) and (ip_pkt.dst != client_ip):
            # Uninteresting destination IP address
            continue

        tcp_pkt = ip_pkt[TCP]


        if (tcp_pkt.sport != int(server_port) and tcp_pkt.sport != int(client_port)):
            continue
        if (tcp_pkt.dport != int(server_port) and tcp_pkt.dport != int(client_port)):
            continue



        interesting_packet_count += 1

        if interesting_packet_count == 1:
            first_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            first_pkt_timestamp_resoluton = pkt_metadata.tsresol
            first_pkt_ordinal = count
        last_pkt_timestamp = (pkt_metadata.tshigh << 32 ) | pkt_metadata.tslow
        last_pkt_timestamp_resolution = pkt_metadata.tsresol
        last_pkt_ordinal = count


    print ('%s contains of all the %s , intersting packagees %s' %(file_name, count, interesting_packet_count))
#    print ('First package in connection : Packet# %s %s' %(first_pkt_ordinal, printable_timestamp(first_pkt_timestamp,first_pkt_timestamp_resoluton)))
    print ('Last package in connection: Packet # %s %s' %(last_pkt_ordinal, printable_timestamp(last_pkt_timestamp,last_pkt_timestamp_resolution)))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>', help='pcap file to parse', required=True)
    parser.add_argument('--server', metavar=' <server address>', help=' specify the server address', required=True)
    parser.add_argument('--client', metavar=' <client address>', help=' specify the  client address', required=False)

    args = parser.parse_args()
    file_name = args.pcap
    server = args.server
    client = args.client

    if not os.path.isfile(file_name):
        print('"{}" does not exists'.format(file_name))
        sys.exit(-1)

    process_pcap(file_name, server, client)
    sys.exit(0)

