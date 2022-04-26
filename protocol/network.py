from .protocol import *
from enum import *
import sys
import struct

class NetType(Enum):
    NETTYPE_UNKNOWN = 0
    NETTYPE_IPV4 = 1
    NETTYPE_IPV6 = 2

class NetworkLayer(Protocol):
    class IPv4(Protocol):
        # NetworkLayer::IPv4
        def __init__(self):
            self.protocolName = 'internet protocol version 4'

        def parse(self, stream, offset=0):
            return True

        def toString(self, indentationLevel=0):
            return ''

        def size(self):
            return 0

    class IPv6(Protocol):
        # NetworkLayer::IPv6
        def __init__(self):
            self.protocolName = 'internet protocol version 6'

        def parse(self, stream, offset=0):
            return True

        def toString(self, indentationLevel=0):
            return ''

        def size(self):
            return 0

    def __init__(self, nettype=NetType.NETTYPE_UNKNOWN):
        self.protocolName = 'network'
        self.netType = nettype

    def parse(self, stream, offset=0):
        return True

    def toString(self, indentationLevel=0):
        return ''

    def size(self):
        return 0

