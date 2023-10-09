from tqdm import tqdm
import pyshark
import os.path
import time
import json
import sys


class CAP:
    def __init__(self, pcap_file_path: str):
        self.capture = self.init(pcap_file_path)
        self.file_in = pcap_file_path
        self.hosts = []
        self.events = self.parse_packets()

    def init(self, file_path):
        if os.path.isfile(file_path):
            return pyshark.FileCapture(file_path)
        else:
            print(f'[X] Cannot find file specified')
            exit(1)

    def parse_packets(self):
        events = {
            'packets': [],
            'hosts': []
        }
        for packet in tqdm(self.capture,desc='Parsing Packets...',total=len(self.capture)):
            event = {'label': '',
                     'source': '',
                     'destination': '',
                     'protocol': '',
                     'timestamp': '',
                     'packet_data': {},

                     }
            name = 'UNKNOWN'
            if packet.highest_layer == 'MDNS':
                dns_fields = list(packet.mdns._all_fields.keys())
                if 'dns.ptr.domain_name' in dns_fields:
                    name = packet.mdns.dns_ptr_domain_name
                elif 'dns.qry.name' in dns_fields:
                    name = packet.mdns.dns_qry_name
                else:
                    try:
                        name = packet.ip.src
                    except AttributeError:
                        pass
            elif packet.highest_layer == 'DNS':
                name = packet.dns
            elif packet.highest_layer == 'DNS' and 'qry.name' in list(packet.dns._all_fields):
                name = dns_query_source(packet)

            elif packet.highest_layer in ['TCP', 'UDP', 'ARP', 'HTTP', 'NBNS','DHCP','SSDP','DNS','MDNS']:
                # packet_readers = {'TCP': TCP.Connection,
                #                   'UDP': UDP.Datagrams,
                #                   'ARP': ARP.AddressResolution,
                #                   'TLS': TLS.TLS,
                #                   'HTTP': HTTP.HTTP,
                #                   'NBNS': NBNS.NetBios
                #                   }
                # Protocols:
                # X TLS         X NBNS
                # x TCP         X UDP
                # X HTTP
                # TODO:
                # - ARP         - LLMNR
                # - RDP         - DHCP
                # - ICMP        - SSDP

                try:
                    event['timestamp'] = time.ctime(float(packet.sniff_timestamp))
                    event['protocol'] = packet.transport_layer
                    event['destination'] = packet.ip.dst
                    event['source'] = packet.ip.src
                    # Generic form with eval doesn't need separate classes at all though just one function...
                    event['packet_data'] = packet2dict(packet)
                except AttributeError:
                    pass
            else:
                # which layer would it be?? ICMP!
                event['timestamp'] = time.ctime(float(packet.sniff_timestamp))
                event['protocol'] = packet.highest_layer
                dst_layers = ''
                src_layers = ''

                if packet.highest_layer == 'ICMPV6':
                    for layer in packet.layers:
                        try:
                            dst_layers += f'|{layer.layer_name}]/{layer.addr_resolved}/{layer.addr_oui_resolved}|'
                            src_layers += f'|{layer.layer_name}]/{layer.src_resolved}/{layer.src_oui_resolved}|'
                            name = layer.opt
                        except AttributeError:
                            try:
                                dst_layers += f'|{layer.layer_name}]/{layer.src_host}|'
                                src_layers += f'|{layer.layer_name}]/{layer.dst_host}|'
                            except AttributeError:
                                pass
                            pass

                event['source'] = src_layers
                event['destination'] = dst_layers
            # Add the packet event to list of packets
            events['packets'].append(event)
            if  event['source'] not in events['hosts']:
                events['hosts'].append( event['source'])

        events['n_packets'] = len(events['packets'])
        start = events['packets'][0]['timestamp']
        stops = events['packets'][-1]['timestamp']
        total = events['n_packets']
        print(f'{total} packets recorded between {start} to {stops}')
        print(f'[+] FINISHED. Saw {len(self.hosts)} unique IPs in {os.path.split(self.capture.input_filepath)[1]}')
        return events

    def save(self):
        data = {'events': self.events, 'ip_addresses': self.hosts}
        log_str = json.dumps(data, indent=2)
        self.file_in = os.path.split(self.file_in)[-1]
        log_out = f'{self.file_in.split(".")[0]}.json'
        with open(log_out, 'w') as f:
            f.write(log_str)
        f.close()
        print(f'[+] Saved {len(self.events["packets"])} Events from PCAP {self.file_in} to {log_out}')




def packet2dict(packet):
    fields = eval(f'packet.{packet.transport_layer.lower()}.field_names')
    result = {
        'packet_size': packet.captured_length,
    }
    for field in fields:
        if len(field):
            result[field] = eval(f'packet.{packet.transport_layer.lower()}.{field}')
    return result



def get_dest_ips(events):
    dest = []
    for event in events:
        dest.append(event['destination'])
    return dest


def get_source_ips(events):
    sources = []
    for event in events:
        source = event['source']
        if len(source.split('.'))>1:
            sources.append(source)
    return sources


def get_tcp_source(packet):
    return f'{packet.ip.src_host}:{packet.tcp.srcport}'


def get_tcp_dest(packet):
    return f'{packet.ip.dst_host}:{packet.tcp.dstport}'


def get_udp_source(packet):
    return f'{packet.ip.addr}:{packet.udp.srcport}'


def get_udp_dest(packet):
    return f'{packet.layers[0].dst_resolved}:{packet.udp.dstport}'


def dns_query_source(packet):
    return packet.dns.qry_name


def main():
    all_cap = CAP("captures\\sample.pcapng")
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        all_cap = CAP(sys.argv[1])
    all_cap.save()


if __name__ == '__main__':
    main()
