from layer_header import LayerHeader
from struct import pack, unpack

class EthernetHeader(LayerHeader):
    def __init__(self, pkt):
        # TODO: Replace the value of header_length with the length of an Ethernet header
        header_length = 14
        
        # TODO: If this header can be variable length, you will need to update the contents of 
        #       self.header_bytes once you know the full length of the header in order to ensure
        #       that all of the bytes associated with this header are saved. 
        #       You can leave it as is for now.
        self.header_bytes = pkt[:header_length]

        self.dest_addr = None
        self.source_addr = None
        self.ether_type = None
        
        # TODO: Unpack the header and assign the values to the above variables
        self.header = unpack("!6s6sH", self.header_bytes[:14])
        self.dest_addr = self.header[0]
        self.source_addr = self.header[1]
        self.ether_type = self.header[2] 
        

    def protocol(self):
        return "Ethernet"

    def header_bytes(self):
        return self.header_bytes

    def print_header(self):
        print("")
        print("ETHERNET HEADER: ")
        # Print first line
        print("-"*(32*2+17))
        
        # Compose the header contents
        source_addr_str = "SOURCE: " + self.format_MAC_addr(self.source_addr)
        white_space = (32 - len(source_addr_str))//2
        second_line = "|" + " "*white_space + source_addr_str + " "*white_space + "|"

        dest_addr_str = "DEST: " + self.format_MAC_addr(self.dest_addr)
        white_space = (32 - len(dest_addr_str))//2
        second_line +=  " "*white_space + dest_addr_str + " "*white_space + "|"

        ether_type_str = "TYPE: " + hex(self.ether_type)
        white_space = (16 - len(ether_type_str))//2
        second_line +=  " "*white_space + ether_type_str + " "*white_space + "|"



        # Print the second line
        print(second_line)

        # Print final line
        print("-"*(32*2+17))

        return super().print_header()