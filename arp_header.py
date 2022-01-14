from layer_header import LayerHeader
from struct import pack, unpack

class ARPHeader(LayerHeader):
    def __init__(self, pkt):
        # TODO: Replace the value of header_length with the length of an Ethernet header
        header_length = 28
        
        # TODO: If this header can be variable length, you will need to update the contents of 
        #       self.header_bytes once you know the full length of the header in order to ensure
        #       that all of the bytes associated with this header are saved. 
        #       You can leave it as is for now.
        self.header_bytes = pkt[:header_length]

        self.hardware_type = None
        self.protocol_type = None
        self.hardware_address_len = None
        self.protocol_address_len = None
        self.opcode = None
        self.sender_hardware_address = None
        self.sender_protocol_address = None
        self.target_hardware_address = None
        self.target_protocol_address = None

        # TODO: Unpack the header and assign the values to the above variables
        self.header = unpack("!HHBBH6sI6sI", self.header_bytes[:28])
        self.hardware_type = self.header[0]
        self.protocol_type = self.header[1]
        self.hardware_address_len = self.header[2]
        self.protocol_address_len = self.header[3]
        self.opcode = self.header[4]
        self.sender_hardware_address = self.header[5]
        self.sender_protocol_address = self.header[6]
        self.target_hardware_address = self.header[7]
        self.target_protocol_address = self.header[8]

    def protocol(self):
        return "ARP"

    def header_bytes(self):
        return self.header_bytes

    def print_header(self):
        print("")
        print("ARP HEADER: ")
        line_width = (96+4)

        ####################################################################
        # Print first line
        print("-"*line_width)
        
        # Compose the contents of the first row of the header
        hardware_str = "HTYPE: " + hex(self.hardware_type)
        white_space = (24 - len(hardware_str))//2
        row_str = "|" + " "*white_space + hardware_str + " "*white_space + "|"

        ptype_str = "PTYPE: " + hex(self.protocol_type)
        white_space = (24 - len(ptype_str))//2
        row_str += " "*white_space + ptype_str + " "*white_space + "|"

        hlen_str = "HLEN: " + hex(self.hardware_address_len)
        white_space = (12 - len(hlen_str))//2
        row_str += " "*white_space + hlen_str + " "*white_space + "|"

        plen_str = "PLEN: " + hex(self.protocol_address_len)
        white_space = (12 - len(plen_str))//2
        row_str += " "*white_space + plen_str + " "*white_space + "|"

        oper_str = "OPER: " + hex(self.opcode)
        white_space = (24 - len(oper_str))//2
        row_str += " "*white_space + oper_str + " "*white_space + "|"


        # Print the first row of the header
        print(row_str)


        ####################################################################
        # Print a line divider
        print("-"*121)

        sha_str = "SHA: " + self.format_MAC_addr(self.sender_hardware_address)
        white_space = (72 - len(sha_str))//2
        row_str = " "*white_space + sha_str + " "*white_space + "|"

        spa_str = "SPA: " + self.format_IPv4_addr(self.sender_protocol_address)
        white_space = (48 - len(spa_str))//2
        row_str += " "*white_space + spa_str + " "*white_space + "|"


        # Print the first row of the header
        print(row_str)


        ####################################################################
        # Print a line divider
        print("-"*121)

        tha_str = "THA: " + self.format_MAC_addr(self.target_hardware_address)
        white_space = (72 - len(tha_str))//2
        row_str = " "*white_space + tha_str + " "*white_space + "|"

        tpa_str = "TPA: " + self.format_IPv4_addr(self.target_protocol_address)
        white_space = (48 - len(tpa_str))//2
        row_str += " "*white_space + tpa_str + " "*white_space + "|"
        
        # Print the first row of the header
        print(row_str)

        ####################################################################
        # Print a line divider
        print("-"*121)

        return super().print_header()