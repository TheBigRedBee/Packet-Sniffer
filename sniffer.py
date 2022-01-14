import threading

from link_layer_headers.ethernet_header import EthernetHeader
from network_layer_headers.ipv4_header import IPv4Header
from network_layer_headers.arp_header import ARPHeader
from transport_layer_headers.tcp_header import TCPHeader
from transport_layer_headers.udp_header import UDPHeader

from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
import traceback

class PacketSniffer:
    def __init__(self):
        self.stop_event = threading.Event()
        self.sniffed_packets = []

    def sniff(self):
        pkts = sniff(prn=self.__sniff, stop_filter=lambda p: self.stop_event.is_set())
        return pkts


    def sniff_num_packets(self, num_packets):
        pkts = sniff(prn=self.__sniff, count = num_packets)
        
        #print("Stopped after %i packets" % len(pkts))
        return pkts

        
    def __sniff(self, pkt):
        print()
        print("#" * 100)
        print("RAW BYTES:")
        print(bytes(pkt))

        ethernet_header = ''
        network_header = ''
        transport_header = ''
        final_payload = ''

        try:
            print("Attempting to unpack/decode the received packet...")
            ethernet_header, payload = self.extract_ethernet_header(bytes(pkt))
            # Some packets only have ethernet headers
            if payload:
                network_header, payload = self.extract_network_layer_header(payload, ethernet_header.ether_type)
                # Some packets only have ethernet and network headers
                if payload:
                    transport_header, final_payload = self.extract_transport_layer_header(payload, network_header.transport_protocol)
                    # In theory, it is possible not to have a payload here as well
                    if final_payload:                
                        print("PAYLOAD:")
                        print(final_payload)

            self.sniffed_packets.append({
                'bytes': bytes(pkt),
                'link': ethernet_header,
                'network': network_header,
                'transport': transport_header,
                'payload': final_payload
            })
        except Exception as err:
            print("An error occurred while unpacking this packet. This is not necessarily a problem, as errors are expected for some packet types that we are not processing in this assignment.")
            print(traceback.format_exc())

    # 14 bytes
    # [0:6] Source MAC address
    # [6:12] Destination MAC address
    # [12:14] ETHER_TYPE constant
    def extract_ethernet_header(self, pkt):
        ethernet_header = EthernetHeader(pkt)
        ethernet_header.print_header()
        payload = pkt[ethernet_header.header_length:]

        # Returns the entire header, the payload type, and the payload
        return ethernet_header, payload


    # ETHER_TYPE constants
    # 0x0800 - IPv4
    # 0x0806 - Address Resolution Protocol
    def extract_network_layer_header(self, pkt, type):
        if type == 0x0800:
            return self.extract_IPv4_header(pkt)
        elif type == 0x0806:
            return self.extract_ARP_header(pkt)
        else:
            print("Received unknown network packet type")


    # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    # 0x01 - ICMP
    # 0x06 - TCP
    # 0x11 - UDP 
    def extract_transport_layer_header(self, pkt, type):
        if type == 0x06:
            return self.extract_TCP_header(pkt)
        elif type == 0x11:
            return self.extract_UDP_header(pkt)
        else:
            print("Received unknown transport packet type")


    def extract_IPv4_header(self, pkt):
        ipv4_header = IPv4Header(pkt)
        ipv4_header.print_header()
        payload = pkt[ipv4_header.header_length:]

        # Returns the entire header and the payload
        return ipv4_header, payload


    def extract_ARP_header(self, pkt):
        arp_header = ARPHeader(pkt)
        arp_header.print_header()

        # Returns the entire header and the payload
        return arp_header, None


    def extract_TCP_header(self, pkt):
        tcp_header = TCPHeader(pkt)
        tcp_header.print_header()
        payload = pkt[tcp_header.header_length:]
        # Returns the entire header and the payload
        return tcp_header, payload


    def extract_UDP_header(self, pkt):
        udp_header = UDPHeader(pkt)
        udp_header.print_header()
        payload = pkt[udp_header.header_length:]
        # Returns the entire header and the payload
        return udp_header, payload

if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.sniff_num_packets(100)
