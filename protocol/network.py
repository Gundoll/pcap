from .protocol import *
from .transport import *
from enum import *
import sys
import struct

class NetType(Enum):
    NETTYPE_UNKNOWN = 0
    NETTYPE_IPV4 = 1
    NETTYPE_IPV6 = 2

class IpProtocolNumber(Enum):
    IPNUM_HOPOPT = 0
    IPNUM_ICMP = 1
    IPNUM_IGMP = 2
    IPNUM_GGP = 3
    IPNUM_IP_IN_IP = 4
    IPNUM_ST = 5
    IPNUM_TCP = 6
    IPNUM_CBT = 7
    IPNUM_EGP = 8
    IPNUM_IGP = 9
    IPNUM_BBN_RCC_MON = 10
    IPNUM_NVP_II = 11
    IPNUM_PUP = 12
    IPNUM_ARGUS = 13
    IPNUM_EMCON = 14
    IPNUM_XNET = 15
    IPNUM_CHAOS = 16
    IPNUM_UDP = 17
    IPNUM_MUX = 18
    IPNUM_DCN_MEAS = 19
    IPNUM_HMP = 20
    IPNUM_PRM = 21
    IPNUM_XNS_IDP = 22
    IPNUM_TRUNK_1 = 23
    IPNUM_TRUNK_2 = 24
    IPNUM_LEAF_1 = 25
    IPNUM_LEAF_2 = 26
    IPNUM_RDP = 27
    IPNUM_IRTP = 28
    IPNUM_ISO_TP4 = 29
    IPNUM_NETBLT = 30
    IPNUM_MFE_NSP = 31
    IPNUM_MERIT_INP = 32
    IPNUM_DCCP = 33
    IPNUM_3PC = 34
    IPNUM_IDPR = 35
    IPNUM_XTP = 36
    IPNUM_DDP = 37
    IPNUM_IDPR_CMTP = 38
    IPNUM_TPPP = 39
    IPNUM_IL = 40
    IPNUM_IPV6 = 41
    IPNUM_SDRP = 42
    IPNUM_IPV6_ROUTE = 43
    IPNUM_IPV6_FRAG = 44
    IPNUM_IDRP = 45
    IPNUM_RSVP = 46
    IPNUM_GRE = 47
    IPNUM_DSR = 48
    IPNUM_BNA = 49
    IPNUM_ESP = 50
    IPNUM_AH = 51
    IPNUM_I_NLSP = 52
    IPNUM_SWIPES = 53
    IPNUM_NARP = 54
    IPNUM_MOBILE = 55
    IPNUM_TLSP = 56
    IPNUM_SKIP = 57
    IPNUM_IPV6_ICMP = 58
    IPNUM_IPV6_NONXT = 59
    IPNUM_IPV6_OPTS = 60
    IPNUM_HOST_INTERNAL_PROTOCOL = 61
    IPNUM_CFTP = 62
    IPNUM_LOCAL_NETWORK = 63
    IPNUM_SAT_EXPAK = 64
    IPNUM_KRYPTOLAN = 65
    IPNUM_RVD = 66
    IPNUM_IPPC =67
    IPNUM_DIST_FILESYSTEM = 68
    IPNUM_SAT_MON = 69
    IPNUM_VISA = 70
    IPNUM_IPCU = 71
    IPNUM_CPNX = 72
    IPNUM_CPHB = 73
    IPNUM_WSN = 74
    IPNUM_PVP = 75
    IPNUM_BR_SAT_MON = 76
    IPNUM_SUN_ND = 77
    IPNUM_WB_MON = 78
    IPNUM_WB_EXPAK = 79
    IPNUM_ISO_IP = 80
    IPNUM_VMTP = 81
    IPNUM_SECURE_VMTP = 82
    IPNUM_VINES = 83
    IPNUM_IPTM = 84
    IPNUM_NSFNET_IGP = 85
    IPNUM_DGP = 86
    IPNUM_TCF = 87
    IPNUM_EIGRP = 88
    IPNUM_OSPF =89
    IPNUM_SPRITE_RPC = 90
    IPNUM_LARP = 91
    IPNUM_MTP = 92
    IPNUM_AX_25 = 93
    IPNUM_OS = 94
    IPNUM_MICP = 95
    IPNUM_SCC_SP = 96
    IPNUM_ETHERIP = 97
    IPNUM_ENCAP = 98
    IPNUM_PRIVATE_ENCRYPTION_SCHEME = 99
    IPNUM_GMTP = 100
    IPNUM_IFMP = 101
    IPNUM_PNNI = 102
    IPNUM_PIM = 103
    IPNUM_ARIS = 104
    IPNUM_SCPS = 105
    IPNUM_QNX = 106
    IPNUM_AN = 107
    IPNUM_IP_COMP = 108
    IPNUM_SNP = 109
    IPNUM_COMPAQ_PEER = 110
    IPNUM_IPX_IN_IP = 111
    IPNUM_VRRP = 112
    IPNUM_PGM = 113
    IPNUM_ZERO_HOP_PROTOCOL = 114
    IPNUM_L2TP = 115
    IPNUM_DDX = 116
    IPNUM_IATP = 117
    IPNUM_STP = 118
    IPNUM_SRP = 119
    IPNUM_UTI = 120
    IPNUM_SMP = 121
    IPNUM_SM = 122
    IPNUM_PTP = 123
    IPNUM_IS_IS_OVER_IPV4 = 124
    IPNUM_FIRE = 125
    IPNUM_CRTP = 126
    IPNUM_CRUDP = 127
    IPNUM_SSCOPMCE = 128
    IPNUM_IPLT = 129
    IPNUM_SPS = 130
    IPNUM_PIPE = 131
    IPNUM_SCTP = 132
    IPNUM_FC = 133
    IPNUM_RSVP_E2E_IGNORE = 134
    IPNUM_MOBILITY_HEADER = 135
    IPNUM_UDP_LITE = 136
    IPNUM_MPLS_IN_IP = 137
    IPNUM_MANET = 138
    IPNUM_HIP = 139
    IPNUM_SHIM6 = 140
    IPNUM_WESP = 141
    IPNUM_ROHC = 142
    IPNUM_ETHERNET = 143

TransportTypeDict = {
        IpProtocolNumber.IPNUM_UDP : TransportType.TRANSPORTTYPE_UDP,
        IpProtocolNumber.IPNUM_TCP : TransportType.TRANSPORTTYPE_TCP
}

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
            content = None
            contentType = None
            upperLayerType = None
            try:
                contentType = IpProtocolNumber(self.protocolId)
                upperLayerType = TransportTypeDict[contentType]
                content = TransportLayer(upperLayerType)
            except:
                contentType = None
                upperLayerType = None
                content = None
            return content

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

            # TODO: parse next headers

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
            # TODO: calculate total header length
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
        message += f'{indentation}protocol: {self.protocolName},\n'
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

