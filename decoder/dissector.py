from tqdm import tqdm
import pyshark
import os.path
import time
import json
import sys


def analyze_capture(pcap_path: str):
    network_capture = {}
    capture = pyshark.FileCapture(pcap_path)
    resolvers = {'dhcp': parse_dhcp,
                 'igmp': parse_igmp,
                 'mdns': parse_mdns,
                 'ssdp': parse_ssdp,
                 'eth': parse_eth,
                 'arp': parse_arp,
                 'tcp': parse_tcp,
                 'udp': parse_udp,
                 'tls': parse_tls,
                 'dns': parse_dns,
                 'ip': parse_ip_layer}

    # Could probably look aat the capture up front before iterating...
    for packet in tqdm(capture):
        t = packet.sniff_time
        layers = packet.layers
        endpoint_data = []
        for layer in layers:
            version = layer.layer_name
            if version in resolvers.keys():
                endpoint_data.append([layer.layer_name.upper(), resolvers[version](layer)])
            else:
                try:
                    print(f'TODO: Make dissector for {layer.layer_name}')
                except AttributeError:
                    pass
        # store endpoint data parsed
        network_capture[str(t)] = endpoint_data
        # Parse any payloads or data in packets

    # Post Process Data
    #  - Look at endpoints that conversed (stats, etc.)
    #  - consider or calculate timescales/data rates
    return network_capture


def parse_eth(packet):
    data = {'dst': packet.dst,
            'src': packet.src}
    if 'src_oui_resolved' in packet.field_names:
        data['src_type'] = packet.src_oui_resolved
    if 'addr_oui_resolved' in packet.field_names:
        data['dst_type'] = packet.addr_oui_resolved
    return data


def parse_arp(packet):
    return {'dst': [packet.dst_proto_ipv4, packet.dst_hw_mac],
            'src': [packet.src_proto_ipv4, packet.src_hw_mac]}


def parse_ip_layer(packet):
    return {'dst': packet.dst, 'src': packet.src}


def parse_dhcp(packet):
    data = {}
    elmts = packet.field_names
    if 'cookie' in elmts:
        data['cookie'] = packet.cookie
    if 'hw_mac_addr' in elmts:
        data['MAC'] = packet.hw_mac_addr
    if 'ip_server' in elmts:
        data['server'] = packet.ip_server
    if 'ip_your' in elmts:
        data['client'] = packet.ip_your
    if 'option_router' in elmts:
        data['router'] = packet.option_router
    return data


def parse_udp(packet):
    data = {}
    elmts = packet.field_names
    if 'checksum' in elmts:
        data['chksum'] = packet.checksum
    if 'dstport' in elmts:
        data['dstport'] = packet.dstport
    if 'srcport' in elmts:
        data['srcport'] = packet.srcport
    if 'payload' in elmts:
        data['payload'] = unpack_payload(packet.payload)
    return data


def parse_tcp(packet):
    data = {'flags': {}}
    elmts = packet.field_names

    flags = {'ack': False, 'ae': False, 'cwr': False, 'ece': False,
             'fin': False, 'push': False, 'res': False, 'reset': False,
             'syn': False, 'urg': False}
    for flagType in flags.keys():
        f = f'flags_{flagType}'
        states = {'True': 1, 'False': 0}
        if f in elmts:
            state = states[eval(f'packet.{f}')]
            data['flags'][flagType] = state
    if 'checksum' in elmts:
        data['chksum'] = packet.checksum
    if 'dstport' in elmts:
        data['dstport'] = packet.dstport
    if 'srcport' in elmts:
        data['srcport'] = packet.srcport
    if 'seq_raw' in elmts:
        data['seq'] = packet.seq_raw
    return data


def parse_dns(packet):
    data = {}
    elmts = packet.field_names

    if 'qry_name' in elmts:
        data['query'] = packet.qry_name

    return data


def parse_igmp(packet):
    data = {}
    elmts = packet.field_names
    if 'maddr' in elmts:
        data['maddr'] = packet.maddr
    if 'checksum' in elmts:
        data['cksum'] = packet.checksum
    return data


def parse_mdns(packet):
    data = {}
    elmts = packet.field_names
    return data


def parse_ssdp(packet):
    data = {}
    elmts = packet.field_names
    if 'http_request_method' in elmts:
        data['msg'] = packet.http_chat
    if 'http_host' in elmts:
        data['remote'] = packet.http_host
    if 'http_location' in elmts:
        data['host'] = packet.http_host
    return data


def parse_tls(packet):
    data = {}
    elmts = packet.field_names



    return data


# TODO: nbns
# TODO: DATA
# TODO: http
# TODO: llmnr
# TODO: data-text-lines
# TODO: ipv6

def unpack_payload(data):
    decoded = []
    for nyb in data.split(':'):
        decoded.append(int(nyb, 16))
    return decoded


def usage():
    print(f'Usage: ')
    return

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        pcapfile = sys.argv[1]
        fout = pcapfile.split('.')[0]
        example = analyze_capture(pcapfile)
        open(f'decoded_{fout}.json', 'w').write(json.dumps(example,indent=2))