from .protocol import *
from .network import *
from enum import *
import sys
import struct

class LinkType(Enum):
    LINKTYPE_NULL = 0
    LINKTYPE_ETHERNET = 1
    LINKTYPE_AX25 = 3
    LINKTYPE_IEEE802_5 = 6
    LINKTYPE_ARCNET_BSD = 7
    LINKTYPE_SLIP = 8
    LINKTYPE_PPP = 9
    LINKTYPE_FDDI = 10
    LINKTYPE_PPP_HDLC = 50
    LINKTYPE_PPP_ETHER = 51
    LINKTYPE_ATM_RFC1483 = 100
    LINKTYPE_RAW = 101
    LINKTYPE_C_HDLC = 104
    LINKTYPE_IEEE802_11 = 105
    LINKTYPE_FRELAY = 107
    LINKTYPE_LOOP = 108
    LINKTYPE_LINUX_SLL = 113
    LINKTYPE_LTALK = 114
    LINKTYPE_PFLOG = 117
    LINKTYPE_IEEE802_11_PRISM = 119
    LINKTYPE_IP_OVER_FC = 122
    LINKTYPE_SUNATM = 123
    LINKTYPE_IEEE802_11_RADIOTAP = 127
    LINKTYPE_ARCNET_LINUX = 129
    LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138
    LINKTYPE_MTP2_WITH_PHDR = 139
    LINKTYPE_MTP2 = 140
    LINKTYPE_MTP3 = 141
    LINKTYPE_SCCP = 142
    LINKTYPE_DOCSIS = 143
    LINKTYPE_LINUX_IRDA = 144
    LINKTYPE_USER0 = 147
    LINKTYPE_USER1 = 148
    LINKTYPE_USER2 = 149
    LINKTYPE_USER3 = 150
    LINKTYPE_USER4 = 151
    LINKTYPE_USER5 = 152
    LINKTYPE_USER6 = 153
    LINKTYPE_USER7 = 154
    LINKTYPE_USER8 = 155
    LINKTYPE_USER9 = 156
    LINKTYPE_USER10 = 157
    LINKTYPE_USER11 = 158
    LINKTYPE_USER12 = 159
    LINKTYPE_USER13 = 160
    LINKTYPE_USER14 = 161
    LINKTYPE_USER15 = 162
    LINKTYPE_IEEE802_11_AVS = 163
    LINKTYPE_BACNET_MS_TP = 165
    LINKTYPE_PPP_PPPD = 166
    LINKTYPE_GPRS_LLC = 169
    LINKTYPE_GPF_T = 170
    LINKTYPE_GPF_F = 171
    LINKTYPE_LINUX_LAPD = 177
    LINKTYPE_MFR = 182
    LINKTYPE_BLUETOOTH_HCI_H5 = 187
    LINKTYPE_USB_LINUX = 189
    LINKTYPE_PPI = 192
    LINKTYPE_IEEE802_15_4_WITHHFCS = 195
    LINKTYPE_SITA = 196
    LINKTYPE_ERF = 197
    LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201
    LINKTYPE_AX25_KISS = 202
    LINKTYPE_LAPD = 203
    LINKTYPE_PPP_WITH_DIR = 204
    LINKTYPE_C_HDLC_WITH_DIR = 205
    LINKTYPE_FRELAY_WITH_DIR = 206
    LINKTYPE_LAPD_WITH_DIR = 207
    LINKTYPE_IPMB_LINUX = 209
    LINKTYPE_FLEXRAY = 210
    LINKTYPE_LIN = 212
    LINKTYPE_IEEE802_15_4_NONASK_PHY = 215
    LINKTYPE_USB_LINUX_MMAPPED = 220
    LINKTYPE_FC_2 = 224
    LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225
    LINKTYPE_IPNET = 226
    LINKTYPE_CAN_SOCKETCAN = 227
    LINKTYPE_IPV4 = 228
    LINKTYPE_IPV6 = 229
    LINKTYPE_IEEE802_15_4_NOFCS = 230
    LINKTYPE_DBUS = 231
    LINKTYPE_DVB_CI = 235
    LINKTYPE_MUX27010 = 236
    LINKTYPE_STANAG_5066_D_PDU = 237
    LINKTYPE_NFLOG = 239
    LINKTYPE_NETANALYZER = 240
    LINKTYPE_NETANALYZER_TRANSPARENT = 241
    LINKTYPE_IPOIB = 242
    LINKTYPE_MPEG_2_TS = 243
    LINKTYPE_NG40 = 244
    LINKTYPE_NFC_LLCP = 245
    LINKTYPE_INFINIBAND = 247
    LINKTYPE_SCTP = 248
    LINKTYPE_USBPCAP = 249
    LINKTYPE_RTAC_SERIAL = 250
    LINKTYPE_BLUETOOTH_LE_LL = 251
    LINKTYPE_NETLINK = 253
    LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254
    LINKTYPE_BLUETOOTH_BREDR_BB = 255
    LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256
    LINKTYPE_PROFIBUS_DL = 257
    LINKTYPE_PKTAP = 258
    LINKTYPE_EPON = 259
    LINKTYPE_IPMI_HPM_2 = 260
    LINKTYPE_ZWAVE_R1_R2 = 261
    LINKTYPE_ZWAVE_R3 = 262
    LINKTYPE_WATTSTOPPER_DLM = 263
    LINKTYPE_ISO_14443 = 264
    LINKTYPE_RDS = 265
    LINKTYPE_USB_DARWIN = 266
    LINKTYPE_SDLC = 268
    LINKTYPE_LORATAP = 270
    LINKTYPE_VSOCK = 271
    LINKTYPE_NORDIC_BLE = 272
    LINKTYPE_DOCSIS31_XRA31 = 273
    LINKTYPE_ETHERNET_MPACKET = 274
    LINKTYPE_DISPLAYPORT_AUX = 275
    LINKTYPE_LINUX_SLL2 = 276
    LINKTYPE_OPENVIZSLA = 278
    LINKTYPE_EBHSCR = 279
    LINKTYPE_VPP_DISPATCH = 280
    LINKTYPE_DSA_TAG_BRCM = 281
    LINKTYPE_DSA_TAG_BRCM_PREPEND = 282
    LINKTYPE_IEEE802_15_4_TAP = 283
    LINKTYPE_DSA_TAG_DSA = 284
    LINKTYPE_DSA_TAG_EDSA = 285
    LINKTYPE_ELEE = 286
    LINKTYPE_Z_WAVE_SERIAL = 287
    LINKTYPE_USB_2_0 = 288
    LINKTYPE_ATCS_ALP = 289
    LINKTYPE_ETW = 290
    LINKTYPE_ZBOSS_NCP = 292

class EtherType(Enum):
    ETHERTYPE_IEEE802_3_LENGTH = 0x0000
    ETHERTYPE_EXPERIMENTAL = 0x0101
    ETHERTYPE_XEROX_PUP = 0x0200
    ETHERTYPE_XEROX_PUP_ADDR_TRANS = 0x0201
    ETHERTYPE_NIXDORF = 0x0400
    ETHERTYPE_XEROX_NS_IDP = 0x0600
    ETHERTYPE_DLOG_0 = 0x0660
    ETHERTYPE_DLOG_1 = 0x0661
    ETHERTYPE_IPV4 = 0x0800
    ETHERTYPE_X75_INTERNET = 0x0801
    ETHERTYPE_NBS_INTERNET = 0x0802
    ETHERTYPE_ECMA_INTERNET = 0x0803
    ETHERTYPE_CHAOSNET = 0x0804
    ETHERTYPE_X25_LEVEL_3 = 0x0805
    ETHERTYPE_ARP = 0x0806
    ETHERTYPE_XNS_COMPATABILITY = 0x0807
    ETHERTYPE_FRAME_RELAY_ARP = 0x0808
    ETHERTYPE_SYMBOLICS_PRIVATE_1 = 0x081C
    ETHERTYPE_XYPLEX_1 = 0x0888#-088A
    ETHERTYPE_UNGERMANN_BASS_NET_DEBUGER = 0x900
    ETHERTYPE_XEROX_IEEE802_3_PUP = 0x0A00
    ETHERTYPE_XEROX_IEEE802_3_PUP_ADDR_TRANS = 0x0A01
    ETHERTYPE_BANYAN_VINES = 0x0BAD
    ETHERTYPE_VINES_LOOPBACK = 0x0BAE
    ETHERTYPE_VINES_ECHO = 0x0BAF
    ETHERTYPE_BERKELEY_TRAILER_NEGO = 0x1000
    ETHERTYPE_BERKELEY_TRAILER_ENCAP_IP = 0x1001#-100F
    ETHERTYPE_VALID_SYSTEMS = 0x1600
    ETHERTYPE_TRILL = 0x22F3
    ETHERTYPE_L2_IS_IS = 0x22F4
    ETHERTYPE_PCS_BASIC_BLOCK_PROTOCOL = 0x4242
    ETHERTYPE_BBN_SIMNET = 0x5208
    ETHERTYPE_DEC_UNASSIGNED_EXP = 0x6000
    ETHERTYPE_DEC_MOP_DUMP_LOAD = 0x6001
    ETHERTYPE_DEC_MOD_REMOTE_CONSOLE = 0x6002
    ETHERTYPE_DEC_DECNET_PHASE_IV_ROUTE = 0x6003
    ETHERTYPE_DEC_LAT = 0x6004
    ETHERTYPE_DEC_DIAGNOSTIC_PROTOCOL = 0x6005
    ETHERTYPE_DEC_CUSTOMER_PROTOCOL = 0x6006
    ETHERTYPE_DEC_LAVC_SCA = 0x6007
    ETHERTYPE_DEC_UNASSIGNED_1 = 0x6008#-6009
    ETHERTYPE_3COM_CORPORATION = 0x6010#-6014
    ETHERTYPE_TRANS_ETHER_BRIDGING = 0x6558
    ETHERTYPE_RAW_FRAME_RELAY = 0x6559
    ETHERTYPE_UNGERMANN_BASS_DOWNLOAD = 0x7000
    ETHERTYPE_UNGERMANN_BASS_DIA_LOOP = 0x7002
    ETHERTYPE_LRT = 0x7020#-7029
    ETHERTYPE_PROTEON = 0x7030
    ETHERTYPE_CABLETRON = 0x7034
    ETHERTYPE_CRONUS_VLN = 0x8003
    ETHERTYPE_CRONUS_DIRECT = 0x8004
    ETHERTYPE_HP_PROBE = 0x8005
    ETHERTYPE_NESTAR = 0x8006
    ETHERTYPE_AT_N_T_1 = 0x8008
    ETHERTYPE_EXCELAN = 0x8010
    ETHERTYPE_SGI_DIAGNOSTICS = 0x8013
    ETHERTYPE_SGI_NETWORK_GAMES = 0x8014
    ETHERTYPE_SGI_RESERVED = 0x8015
    ETHERTYPE_SIG_BOUNCE_SERVER = 0x8016
    ETHERTYPE_APOLLO_DOMAIN = 0x8019
    ETHERTYPE_TYMSHARE = 0x802E
    ETHERTYPE_TIGAN_INC = 0x802F
    ETHERTYPE_RARP = 0x8035
    ETHERTYPE_AEONIC_SYSTEMS = 0x8036
    ETHERTYPE_DEC_LAN_BRIDGE = 0x8038
    ETHERTYPE_DEC_UNASSIGNED_2 = 0x8039#-803C
    ETHERTYPE_DEC_ETHERNET_ENCRYPTION = 0x803D
    ETHERTYPE_DEC_UNASSIGNED_3 = 0x803E
    ETHERTYPE_DEC_LAN_TRAFFIC_MONITOR = 0x803F
    ETHERTYPE_DEC_UNASSIGNED_4 = 0x8040#-8042
    ETHERTYPE_PLANNING_RESEARCH_CORP = 0x8044
    ETHERTYPE_AT_N_T_2 = 0x8046
    ETHERTYPE_AT_N_T_3 = 0x8047
    ETHERTYPE_EXPER_DATA = 0x8049
    ETHERTYPE_STANFORD_V_KERNEL_EXP = 0x805B
    ETHERTYPE_STANFORD_V_KERNEL_PROD = 0x805C
    ETHERTYPE_EVANS_N_SUTHERLAND = 0x805D
    ETHERTYPE_LITTLE_MACHIES = 0x8060
    ETHERTYPE_COUNTERPOINT_COMPUTERS_1 = 0x8062
    ETHERTYPE_UNIV_OF_MASS_AMHERST_1 = 0x8065
    ETHERTYPE_UNIV_OF_MASS_AMHERST_2 = 0x8066
    ETHERTYPE_VEECO_INTEGRATED_AUTO = 0x8067
    ETHERTYPE_GENERAL_DYNAMICS = 0x8068
    ETHERTYPE_AT_N_T_4 = 0x8069
    ETHERTYPE_AUTOPHON = 0x806A
    ETHERTYPE_COMDESIGN = 0x806C
    ETHERTYPE_COMPUTERGRAPHIC_CORP = 0x806D
    ETHERTYPE_LANDMARK_GRAPHICS_CORP = 0x806E#-8077
    ETHERTYPE_MATRA = 0x807A
    ETHERTYPE_DANSK_DATA_ELEKTRONIK = 0x807B
    ETHERTYPE_MERIT_INTERNODAL = 0x807C
    ETHERTYPE_VITALINK_COMMUNICATIONS = 0x807D#-807F
    ETHERTYPE_VITALINK_TRANSLAN_III = 0x8080
    ETHERTYPE_COUNTERPOINT_COMPUTERS_2 = 0x8081#-8083
    ETHERTYPE_APPLETALK = 0x809B
    ETHERTYPE_DATABILITY_1 = 0x809C#-809E
    ETHERTYPE_SPIDER_SYSTEMS_LTD = 0x809F
    ETHERTYPE_NIXDORF_COMPUTERS = 0x80A3
    ETHERTYPE_SIMENS_GAMMASONICS_INC = 0x80A4#-80B3
    ETHERTYPE_DCA_DATA_EXCHANGE_CLUSTER = 0x80C0#-80C3
    ETHERTYPE_BANYAN_SYSTEMS_1 = 0x80C4
    ETHERTYPE_BANYAN_SYSTEMS_2 = 0x80C5
    ETHERTYPE_PACER_SOFTWARE = 0x80C6
    ETHERTYPE_APPLITEK_CORPORATION = 0x80C7
    ETHERTYPE_INTERGRAPH_CORPORATION = 0x80C8#-80CC
    ETHERTYPE_HARRIS_CORPORATION = 0x80CD#-80CE
    ETHERTYPE_TAYLOR_INSTRUMENT = 0x80CF#-80D2
    ETHERTYPE_ROSEMOUNT_CORPORATION = 0x80D3#-80D4
    ETHERTYPE_IBM_SNA_SERVICE_ON_ETHER = 0x80D5
    ETHERTYPE_VARIAN_ASSOCIATES = 0x80DD
    ETHERTYPE_INTEGRATED_SOLUTIONS_TRFS = 0x80DE#-80DF
    ETHERTYPE_ALLEN_BRADLEY = 0x80E0#-80E3
    ETHERTYPE_DATABILITY_2 = 0x80E4#-80F0
    ETHERTYPE_RETIX = 0x80F2
    ETHERTYPE_APPLETALK_AARP = 0x80F3
    ETHERTYPE_KINETICS = 0x80F4#-80F5
    ETHERTYPE_APOLLO_COMPUTER = 0x80F7
    ETHERTYPE_WELFLEET_COMMUNICATIONS_1 = 0x80FF
    ETHERTYPE_CUSTOMER_VLAN_TAG_TYPE = 0x8100
    ETHERTYPE_WELFLEET_COMMUNICATIONS_2 = 0x8101#-8103
    ETHERTYPE_SYMBOLICS_PRIVATE_2 = 0x8107#-8109
    ETHERTYPE_HAYES_MICROCOMPUTERS = 0x8130
    ETHERTYPE_VG_LABORATORY_SYSTEMS = 0x8131
    ETHERTYPE_BRIDGE_COMMUNICATIONS = 0x8132#-8136
    ETHERTYPE_NOVELL_INC = 0x8137#-8138
    ETHERTYPE_KTI = 0x8139#-813D
    ETHERTYPE_LOGICRAFT = 0x8148
    ETHERTYPE_NETWORK_COMPUTING_DEVICES = 0x8149
    ETHERTYPE_ALPHA_MICRO = 0x814A
    ETHERTYPE_SNMP = 0x814C
    ETHERTYPE_BIIN_1 = 0x814D
    ETHERTYPE_BIIN_2 = 0x814E
    ETHERTYPE_TECHNICALLY_ELITE_CONCEPT = 0x814F
    ETHERTYPE_RATIONAL_CORP = 0x8150
    ETHERTYPE_QUALCOMM_1 = 0x8151#-8153
    ETHERTYPE_COMPUTER_PROTOCOL_PTY_LTD = 0x815C#-815E
    ETHERTYPE_CHARLES_RIVER_DATA_SYSTEM_1 = 0x8164#-8166
    ETHERTYPE_XTP = 0x817D
    ETHERTYPE_SGI_TIME_WARNER_PROP = 0x817E
    ETHERTYPE_HIPPI_FP_ENCAPSULATION = 0x8180
    ETHERTYPE_STP_HIPPI_ST = 0x8181
    ETHERTYPE_RESERVED_FOR_HIPPI_6400_1 = 0x8182
    ETHERTYPE_RESERVED_FOR_HIPPI_6400_2 = 0x8183
    ETHERTYPE_SILICON_GRAPHICS_PROP = 0x8184#-818C
    ETHERTYPE_MOTOROLA_COMPUTER = 0x818D
    ETHERTYPE_QUALCOMM_2 = 0x819A#-81A3
    ETHERTYPE_ARAI_BUNKICHI = 0x81A4
    ETHERTYPE_RAD_NETWORK_DEVICES = 0x81A5#-81AE
    ETHERTYPE_XYPLEX_2 = 0x81B7#-81B9
    ETHERTYPE_APRICOT_COMPUTERS = 0x81CC#-81D5
    ETHERTYPE_ARTISOFT = 0x81D6#-81DD
    ETHERTYPE_POLYGON = 0x81E6#-81EF
    ETHERTYPE_COMSAT_LABS = 0x81F0#-81F2
    ETHERTYPE_SAIC = 0x81F3#-81F5
    ETHERTYPE_VG_ANALYTICAL = 0x81F6#-81F8
    ETHERTYPE_QUANTUM_SOFTWARE = 0x8203#-8205
    ETHERTYPE_ASCOM_BANKING_SYSTEMS = 0x8221#-8222
    ETHERTYPE_ADVANCED_ENCRYPTION_SYSTE = 0x823E#-8240
    ETHERTYPE_ATHENA_PROGRAMMING = 0x827F#-8282
    ETHERTYPE_CHARLES_RIVER_DATA_SYSTEM_2 = 0x8263#-826A
    ETHERTYPE_INST_IND_INFO_TECH = 0x829A#-829B
    ETHERTYPE_TAURUS_CONTROLS = 0x829C#-82AB
    ETHERTYPE_WALKER_RICHER_N_QUINN = 0x82AC#-8693
    ETHERTYPE_IDEA_COURIER = 0x8694#-869D
    ETHERTYPE_COMPUTER_NETWORK_TECH = 0x869E#-86A1
    ETHERTYPE_GATEWAY_COMMUNICATIONS = 0x86A3#-86AC
    ETHERTYPE_SECTRA = 0x86DB
    ETHERTYPE_DELTA_CONTROLS = 0x86DE
    ETHERTYPE_IPV6 = 0x86DD
    ETHERTYPE_ATOMIC = 0x86DF
    ETHERTYPE_LANDIS_N_GYR_POWERS = 0x86E0#-86EF
    ETHERTYPE_MONOROLA = 0x8700#-8710
    ETHERTYPE_TCPIP_COMPRESSION = 0x876B
    ETHERTYPE_IP_AUTONOMOUS_SYSTEMS = 0x876C
    ETHERTYPE_SECURE_DATA = 0x876D
    ETHERTYPE_IEEE_STD_802_3_EPON = 0x8808
    ETHERTYPE_SLOW_PROTOCOLS = 0x8809
    ETHERTYPE_PPP = 0x880B
    ETHERTYPE_GSMP = 0x880C
    ETHERTYPE_ETHERNET_NIC_HW_N_SW_TESTING = 0x8822
    ETHERTYPE_MPLS = 0x8847
    ETHERTYPE_MPLS_WITH_UPSTREAM_ASSIGNED_LABEL = 0x8848
    ETHERTYPE_MCAP = 0x8861
    ETHERTYPE_PPPOE_DISCOVERY_STAGE = 0x8863
    ETHERTYPE_PPPOE_SESSION_STAGE = 0x8864
    ETHERTYPE_IEEE_STD_802_1X_LOCAL_EXPERIMENTAL_ETHERTYPE = 0x888E
    ETHERTYPE_IEEE_STD_802_1Q_S_TAG = 0x88A8
    ETHERTYPE_INVISIBLE_SOFTWARE = 0x8A96#-8A97
    ETHERTYPE_IEEE_STD_802_LOCAL_EXPERIMENTAL_ETHERTYPE_1 = 0x88B5
    ETHERTYPE_IEEE_STD_802_LOCAL_EXPERIMENTAL_ETHERTYPE_2 = 0x88B6
    ETHERTYPE_IEEE_STD_802_OUI_EXTENDED_ETHERTYPE = 0x88B7
    ETHERTYPE_IEEE_STD_802_11I = 0x88C7
    ETHERTYPE_IEEE_STD_802_1AB_LLDP  = 0x88CC
    ETHERTYPE_IEEE_STD_802_1AE_MACS = 0x88E5
    ETHERTYPE_PROVIDER_BACKBONE_BRIDGING_INSTANCE_TAG = 0x88E7
    ETHERTYPE_IEEE_STD_802_1Q_MVRP = 0x88F5
    ETHERTYPE_IEEE_STD_802_1Q_MMRP = 0x88F6
    ETHERTYPE_IEEE_STD_802_11R = 0x890D
    ETHERTYPE_IEEE_STD_802_21_MIHP = 0x8917
    ETHERTYPE_IEEE_STD_802_1QBE = 0x8929
    ETHERTYPE_TRILL_FGL = 0x893B
    ETHERTYPE_IEEE_STD_802_1QBG = 0x8940
    ETHERTYPE_TRILL_RBRIDGE_CHANNEL = 0x8946
    ETHERTYPE_GEONETWORKING_AS_DEFINED_IN_ETSI_EN_203_636_4_1 = 0x8947
    ETHERTYPE_NSH = 0x894F
    ETHERTYPE_LOOPBACK = 0x9000
    ETHERTYPE_3COM_XNS_SYS_MGMT = 0x9001
    ETHERTYPE_3COM_TCPIP_SYS = 0x9002
    ETHERTYPE_3COM_LOOP_DETECT = 0x9003
    ETHERTYPE_MULTI_TOPOLOGY = 0x9A22
    ETHERTYPE_LOWPAN_ENCAPSULATION = 0xA0ED
    ETHERTYPE_CHANNEL_CONTROL = 0xB7EA
    ETHERTYPE_BBN_VITAL_LANBRIDGE_CACHE = 0xFF00
    ETHERTYPE_ISC_BUNKER_RAMO = 0xFF00#-FF0F
    ETHERTYPE_RESERVED = 0xFFFF

NetTypeDict = {
        EtherType.ETHERTYPE_IPV4 : NetType.NETTYPE_IPV4,
        EtherType.ETHERTYPE_IPV6 : NetType.NETTYPE_IPV6
}

class LinkLayer(Protocol):
    class LinuxSLL(Protocol):
        # LinkLayer::LinuxSLL
        def __init__(self):
            self.protocolName = 'linux cooked capture'
            self.packetType = 0
            self.addressType = 0
            self.addressLength = 0
            self.sourceAddress = 0
            self.protocolType = 0

        # LinkLayer::LinuxSLL
        def parse(self, stream, offset=0):
            self.packetType = int.from_bytes(stream[offset:offset+2], byteorder='big')
            self.addressType = int.from_bytes(stream[offset+2:offset+4], byteorder='big')
            self.addressLength = int.from_bytes(stream[offset+4:offset+6], byteorder='big')
            self.sourceAddress = stream[offset+6:offset+14]
            self.protocolType = int.from_bytes(stream[offset+14:offset+16], byteorder='big')
            return True

        # LinkLayer::LinuxSLL
        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            message += f'{indentation}packet type: {self.packetType},\n'
            message += f'{indentation}address type: {self.addressType},\n'
            message += f'{indentation}address length: {self.addressLength},\n'
            message += f'{indentation}source address: '
            for idx in range(self.addressLength):
                message += '%02x'%self.sourceAddress[idx]
                if idx < self.addressLength-1:
                    message += ':'
                else:
                    message += ',\n'
            message += f'{indentation}protocol type: 0x{self.protocolType:04x},\n'
            return message

        # LinkLayer::LinuxSLL
        def size(self):
            return 2 + 2 + 2 + 8 + 2

        # LinkLayer::LinuxSLL
        def createContent(self):
            content = None
            contentType = None
            netType = None
            try:
                contentType = EtherType(self.protocolType)
                netType = NetTypeDict[contentType]
            except:
                contentType =  None
                netType = NetType.NETTYPE_UNKNOWN

            if contentType == EtherType.ETHERTYPE_IPV4:
                content = NetworkLayer(netType)
                return content

            return None

    class Ethernet(Protocol):
        # LinkLayer::Ethernet
        class EthernetKind(Enum):
            UNKNOWN = 0
            ETHERNET_II = 1
            LLC = 2
            SNAP = 3
            NOVELL = 4

        # LinkLayer::Ethernet
        def __init__(self):
            self.protocolName = 'ethernet'
            self.dstAddress = []
            self.srcAddress = []
            self.etherType = 0
            self.kind = LinkLayer.Ethernet.EthernetKind.UNKNOWN

        # LinkLayer::Ethernet
        def parse(self, stream, offset=0):
            self.dstAddress = struct.unpack('BBBBBB', stream[offset:offset+6])
            self.srcAddress = struct.unpack('BBBBBB', stream[offset+6:offset+12])
            self.etherType = int.from_bytes(stream[offset+12:offset+14], byteorder='big')

            if self.etherType >= 0x0600:
                self.protocolName = 'ethernet ii'
                self.kind = LinkLayer.Ethernet.EthernetKind.ETHERNET_II
            elif self.etherType < 0x05dc:
                ethernetChecker = int.from_bytes(stream[offset+14:offset+16], byteorder='big')
                if ethernetChecker == 0xffff:
                    self.protocolName = 'ethernet novell raw ieee 802.3 non-standard variation'
                    self.kind = LinkLayer.Ethernet.EthernetKind.NOVELL
                elif ethernetChecker == 0xaaaa:
                    self.protocolName = 'ethernet ieee 802.2 subnetwork access protocol'
                    self.kind = LinkLayer.Ethernet.EthernetKind.SNAP
                else:
                    self.protocolName = 'ethernet ieee 802.2 logical link control'
                    self.kind = LinkLayer.Ethernet.EthernetKind.LLC
            else:
                self.body = None

            return True

        # LinkLayer::Ethernet
        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            message += f'{indentation}destination mac: {self.dstAddress[0]:02x}:{self.dstAddress[1]:02x}:{self.dstAddress[2]:02x}:{self.dstAddress[3]:02x}:{self.dstAddress[4]:02x}:{self.dstAddress[5]:02x}\n'
            message += f'{indentation}source mac: {self.srcAddress[0]:02x}:{self.srcAddress[1]:02x}:{self.srcAddress[2]:02x}:{self.srcAddress[3]:02x}:{self.srcAddress[4]:02x}:{self.srcAddress[5]:02x}\n'
            message += f'{indentation}ethernet type: {self.etherType}\n'
            return message

        # LinkLayer::Ethernet
        def size(self):
            return 6 + 6 + 2

        # LinkLayer::Ethernet
        def createContent(self):
            if self.kind == LinkLayer.Ethernet.EthernetKind.ETHERNET_II:
                content = None
                contentType = None
                netType = None
                try:
                    contentType = EtherType(self.etherType)
                    netType = NetTypeDict[contentType]
                except:
                    contentType =  None
                    netType = NetType.NETTYPE_UNKNOWN

                if contentType == EtherType.ETHERTYPE_IPV4:
                    content = NetworkLayer(netType)
                    return content
                elif contentType == EtherType.ETHERTYPE_ARP:
                    # TODO: return NetworkLayer::ARP
                    return None
                elif contentType == EtherType.ETHERTYPE_IPV6:
                    content = NetworkLayer(netType)
                    return content
            elif self.kind == LinkLayer.Ethernet.EthernetKind.LLC:
                return None
            elif self.kind == LinkLayer.Ethernet.EthernetKind.SNAP:
                return None
            elif self.kind == LinkLayer.Ethernet.EthernetKind.NOVELL:
                return None
            else:
                return None
            return None

    # LinkLayer
    def __init__(self):
        self.protocolName = 'link layer'
        self.header = None
        self.content = None

    # LinkLayer
    def parse(self, stream, offset=0, linktype=0):
        try:
            linkType = LinkType(linktype)
        except:
            return False

        if linkType == LinkType.LINKTYPE_LINUX_SLL:
            self.header = LinkLayer.LinuxSLL()
        elif linkType == LinkType.LINKTYPE_ETHERNET:
            self.header = LinkLayer.Ethernet()

        self.header.parse(stream, offset)

        offset += self.header.size()

        self.content = self.header.createContent()
        if self.content:
            self.content.parse(stream, offset)

        return True

    # LinkLayer
    def toString(self, indentationLevel=0):
        indentation = makeIndentation(indentationLevel)
        message = ''
        message += f'{indentation}protocol: {self.header.protocolName},\n'
        message += f'{indentation}header: {{\n'
        message += f'{self.header.toString(indentationLevel+1)}'
        message += f'{indentation}}},\n'
        message += f'{indentation}content: {{\n'
        if self.content:
            message += f'{self.content.toString(indentationLevel+1)}'
        else:
            message += f'{indentation}\tNone\n'
        message += f'{indentation}}}\n'
        return message

    # LinkLayer
    def size(self):
        return 0

