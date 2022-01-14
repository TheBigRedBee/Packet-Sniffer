from abc import ABC, abstractmethod
import socket

class LayerHeader(ABC):
    def __init__(self):
        pass

    @property
    @abstractmethod
    def header_bytes(self):
        ...

    @property
    @abstractmethod
    def protocol(self):
        ...

    @abstractmethod
    def print_header(self):
        ...

    @property
    def header_length(self):
        return len(self.header_bytes)

    def format_MAC_addr(self, addr):
        return ':'.join(addr[i:i+1].hex() for i in range(0,6,1))

    def format_IPv4_addr(self, addr):
        return '.'.join([str(addr >> (i << 3) & 0xFF) for i in range(4)[::-1]])
