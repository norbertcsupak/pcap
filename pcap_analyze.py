import argparse
from enum import Enum
import os
import sys
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import time
import pickle
from enum import Enum

class PktDirection(Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2

def printable_timestamp(ts,resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_se_str = time.strftime('%Y-%m-%d %H:%M:%s', time.localtime(ts_sec))
    return  ('%s.%s' %(ts_se_str,ts_subsec))

def print_frames(file_name, srv, cli):
    print (' Opening file : %s' % file_name)
    count = 0
    (server_ip, server_port) = srv.split(':')
    (client_ip, client_port) = cli.split(':')

    for (pkt_data,pkt_metadata) in RawPcapReader(file_name):
        count +=1
        eframe_meta = Ether(pkt_metadata)
        eframe_data = Ether(pkt_data)
        l3_data = eframe_data[IP]
        l4_data = eframe_data[TCP]
        tcp_payload_len = l3_data.len - (l3_data.ihl * 4) - (l4_data.dataofs * 4)
        #print (eframe_data.fields)
        print ('ID:%s  Frame metadata: %s ' % (count, eframe_meta))
        print ('L3_data:%s' % l3_data.fields)
        print ('L4_data:%s' % l4_data.fields)
        print ('L3 frag:%s' % l3_data.frag)
        print ('L4 payload_lenght:%s' % tcp_payload_len)
        if count <10:
            continue
        else:
            break

def create_pickle(pcap_file, pickle_out, srv, cli):
    print('Opening a pcap file for pickling.... %s' % pcap_file)
    count = 0
    interesting_packages = 0
    server_sequence_offset = None
    client_sequence_offset = None

    (server_ip, server_port) = srv.split(':')
    (client_ip, client_port) = cli.split(':')
    packets_for_analysis = []

    for (pkt_data, pkt_metadata) in RawPcapReader(pcap_file):
        count +=1
        ether_pkt = Ether(pkt_data)

        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]

        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        tcp_pkt = ip_pkt[TCP]

        # Determine the TCP payload length. IP fragmentation will mess up this
        # logic, so first check that this is an unfragmented packet
        if (ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
            print('No support for fragmented IP packets')
            return False

        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)

        pkt_data = {}
        pkt_data['src'] = ip_pkt.src
        pkt_data['dest'] = ip_pkt.dst
        pkt_data['ip_flags'] = ip_pkt.flags
        pkt_data['sport'] = tcp_pkt.sport
        pkt_data['dport'] =tcp_pkt.dport

        packets_for_analysis.append(pkt_data)

        print('Writing to  pickle file:%s' % pickle_out )
        with open(pickle_out,'w') as pickle_fd:
            pickle.dump(client,pickle_fd)
            pickle.dump(server,pickle_fd)
            pickle.dump(packets_for_analysis, pickle_fd)
        print ('done.')


def process_pcap(file_name ,srv ,cli):
    print ('Opening {} ...'.format(file_name))
    count = 0
    interesting_packet_count = 0

    (server_ip, server_port) = srv.split(':')
    (client_ip, client_port) = cli.split(':')

    server_sequence_offset = None
    client_sequence_offset = None

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
        tcp_pkt = ip_pkt[TCP]

        if ip_pkt.src == client_ip:
            if tcp_pkt.sport != client_ip:
                continue

            if ip_pkt.dst != server_ip:
                continue

            if tcp_pkt.dport != int(server_port):
                continue

            direction = PktDirection.client_to_server

        elif ip_pkt.src == server_ip:
            if tcp_pkt.sport != int(server_port):
                continue

            if ip_pkt.dst != client_ip:
                continue

            if tcp_pkt.dport != int(client_port):
                continue

            direction = PktDirection.server_to_client

        else :
            continue

        interesting_packet_count += 1

        if interesting_packet_count == 1:
            first_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            first_pkt_timestamp_resoluton = pkt_metadata.tsresol
            first_pkt_ordinal = count
        last_pkt_timestamp = (pkt_metadata.tshigh << 32 ) | pkt_metadata.tslow
        last_pkt_timestamp_resolution = pkt_metadata.tsresol
        last_pkt_ordinal = count

        this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp

        if direction == PktDirection.client_to_server:
            if client_sequence_offset is None:
                client_sequence_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - client_sequence_offset

        else :
            assert direction == PktDirection.server_to_client
            if server_sequence_offset is None:
                server_sequence_offset = tcp_pkt.seq
            relative_offset_seq = tcp_pkt.seq - server_sequence_offset

        if (ip_pkt.flags == 'MF' ) or (ip_pkt.frag != 0 ):
            print('No support for fragmented IP packages')
            break

        tcp_payload_len = ip_pkt.len - (ip_pkt.ihl*4 ) - (tcp_pkt.dataofs * 4)

    print ('%s contains of all the %s , intersting packagees %s' %(file_name, count, interesting_packet_count))
    print ('First package in connection : Packet# %s %s' %(first_pkt_ordinal, printable_timestamp(first_pkt_timestamp,first_pkt_timestamp_resoluton)))
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
    print_frames(file_name, server, client)
    create_pickle(file_name, 'befott', server, client)
    sys.exit(0)

