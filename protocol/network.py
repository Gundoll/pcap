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
            self.version = 0
            self.headerLength = 0
            self.typeOfService = 0
            self.totalPacketLength = 0
            self.identifier = 0
            self.flags = 0
            self.fragmentOffset = 0
            self.ttl = 0
            self.protocolId = 0
            self.headerChecksum = 0
            self.srcAddress = []
            self.dstAddress = []
            self.options = 0

        # NetworkLayer::IPv4
        def parse(self, stream, offset=0):
            self.version = stream[offset] >> 4
            self.headerLength = stream[offset] & 0x0f
            self.typeOfService = stream[offset+1]
            self.totalPacketLength = int.from_bytes(stream[offset+2:offset+4], byteorder='big')
            self.identifier = int.from_bytes(stream[offset+4:offset+6], byteorder='big')
            self.flags = (stream[offset+6] & 0xe0) >> 5
            self.fragmentOffset = int.from_bytes([stream[offset+6] & 0x1f, stream[offset+7]], byteorder='big')
            self.ttl = stream[offset+8]
            self.protocolId = stream[offset+9]
            self.headerChecksum = int.from_bytes(stream[offset+10:offset+12], byteorder='big')
            self.srcAddress = struct.unpack('BBBB', stream[offset+12:offset+16])
            self.dstAddress = struct.unpack('BBBB', stream[offset+12:offset+16])
            return True

        # NetworkLayer::IPv4
        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            message += f'{indentation}version: {self.version},\n'
            message += f'{indentation}header length: {self.headerLength},\n'
            message += f'{indentation}type of service: 0x{self.typeOfService:02x},\n'
            message += f'{indentation}total packet length: {self.totalPacketLength},\n'
            message += f'{indentation}identifier: 0x{self.identifier:04x},\n'
            message += f'{indentation}flags: 0b{self.flags:08b},\n'
            message += f'{indentation}fragment offset: {self.fragmentOffset},\n'
            message += f'{indentation}time to live: {self.ttl},\n'
            message += f'{indentation}protocol id: {self.protocolId},\n'
            message += f'{indentation}header checksum: 0x{self.headerChecksum:04x},\n'
            message += f'{indentation}source ip address: {self.srcAddress[0]}.{self.srcAddress[1]}.{self.srcAddress[2]}.{self.srcAddress[3]},\n'
            message += f'{indentation}destinarion ip address: {self.dstAddress[0]}.{self.dstAddress[1]}.{self.dstAddress[2]}.{self.dstAddress[3]},\n'
            if self.headerLength > 5:
                message += f'{indentation}options: 0x{self.options:x}\n'
            else:
                message += f'{indentation}options: None\n'
            return message

        # NetworkLayer::IPv4
        def size(self):
            return self.headerLength * 4

        # NetworkLayer::IPv4
        def createContent(self):
            return None

    class IPv6(Protocol):
        # NetworkLayer::IPv6
        class HeaderExtensionKind(Enum):
            HEADERKIND_HOP_BY_HOP = 0
            HEADERKIND_TCP = 7
            HEADERKIND_UDP = 17
            HEADERKIND_DEFAUILT = 41
            HEADERKIND_SOURCE_ROUTING = 43
            HEADERKIND_FRAGMENTATION = 44
            HEADERKIND_ESP = 50 # Encapsulating Security Payload
            HEADERKIND_AUTHENTICATION = 51
            HEADERKIND_ICMPV6 = 58
            HEADERKIND_EOH = 59 # End of headers (no next header)
            HEADERKIND_DESTINATION = 60
            HEADERKIND_MOBILITY = 135
            HEADERKIND_HOST_IDENTITY_PROTOCOL = 139
            HEADERKIND_SHIM6_PROTOCOL = 140
            HEADERKIND_EXPERIMENTAL_N_TESTING_1 = 253
            HEADERKIND_EXPERIMENTAL_N_TESTING_2 = 254

        # NetworkLayer::IPv6
        def __init__(self):
            self.protocolName = 'internet protocol version 6'
            self.version = 0
            self.trafficClass = 0
            self.flowLabel = 0
            self.payloadLength = 0
            self.nextHeader = 0
            self.hopLimit = 0
            self.srcAddress = []
            self.dstAddress = []
            self.headerKind = None

        # NetworkLayer::IPv6
        def parse(self, stream, offset=0):
            self.version = stream[offset] >> 4
            self.trafficClass = ((stream[offset] & 0x0f) << 4) + (stream[offset+1] >> 4)
            self.flowLabel = int.from_bytes([stream[offset+1] & 0x0f, stream[offset+2], stream[offset+3]], byteorder='big')
            self.payloadLength = int.from_bytes(stream[offset+4:offset+6], byteorder='big')
            self.nextHeader = stream[offset+6]
            self.hopLimit = stream[offset+7]
            self.srcAddress = struct.unpack('BBBBBBBBBBBBBBBB', stream[offset+8:offset+24])
            self.dstAddress = struct.unpack('BBBBBBBBBBBBBBBB', stream[offset+24:offset+40])

            try:
                self.headerKind = NetworkLayer.IPv6.HeaderExtensionKind(self.nextHeader)
            except:
                self.headerKind = None

            return True

        # NetworkLayer::IPv6
        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            message += f'{indentation}version: {self.version},\n'
            message += f'{indentation}traffic class: 0x{self.trafficClass:02x},\n'
            message += f'{indentation}flow label: 0x{self.flowLabel:05x},\n'
            message += f'{indentation}payload length: {self.payloadLength},\n'
            message += f'{indentation}next header: {self.nextHeader} ({self.headerKind}),\n'
            message += f'{indentation}hop limit: {self.hopLimit},\n'
            message += f'{indentation}source ip address: {self.srcAddress},\n'
            message += f'{indentation}destination ip address: {self.dstAddress}\n'
            return message

        # NetworkLayer::IPv6
        def size(self):
            return 40 # + alpha(depend on the next header chain)

        # NetworkLayer::IPv6
        def createContent(self):
            return None

    # NetworkLayer
    def __init__(self, nettype=NetType.NETTYPE_UNKNOWN):
        self.protocolName = 'network'
        self.netType = nettype
        self.header = None
        self.content = None

    # NetworkLayer
    def parse(self, stream, offset=0):
        # step 1. create network layer header
        if self.netType == NetType.NETTYPE_IPV4:
            self.header = NetworkLayer.IPv4()
        elif self.netType == NetType.NETTYPE_IPV6:
            self.header = NetworkLayer.IPv6()
        else:
            return False

        # step 2. set protocol name
        self.protocolName = self.header.protocolName

        # step 3. parse header
        self.header.parse(stream ,offset)
        offset += self.header.size()

        # step 4. create content
        self.content = self.header.createContent()

        # step 5. parse content
        if self.content:
            self.content.parse(stream, offset)
        else:
            return False

        return True

    # NetworkLayer
    def toString(self, indentationLevel=0):
        indentation = makeIndentation(indentationLevel)
        message = ''
        message += f'{indentation}protocol: {self.header.protocolName},\n'
        message += f'{indentation}header: {{\n'
        if self.header:
            message += self.header.toString(indentationLevel+1)
        else:
            message += f'{indentation}\tNone\n'
        message += f'{indentation}}},\n'
        message += f'{indentation}content: {{\n'
        if self.content:
            message += self.content.toString(indentationLevel+1)
        else:
            message += f'{indentation}\tNone\n'
        message += f'{indentation}}}\n'
        return message

    # NetworkLayer
    def size(self):
        return 0

