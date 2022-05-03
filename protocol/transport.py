from .protocol import *
from enum import *

class TransportType(Enum):
    TRANSPORTTYPE_UNKNOWN = 0
    TRANSPORTTYPE_TCP = 1
    TRANSPORTTYPE_UDP = 2

class TransportLayer(Protocol):
    class TCP(Protocol):
        # TransportLayer::TCP
        def __init__(self):
            self.protocolName = 'transmission control protocol'
            self.sourcePort = 0
            self.destinationPort = 0
            self.sequenceNumber = 0
            self.acknowledgementNumber = 0
            self.headerLength = 0
            self.flags = 0
            self.windowSize = 0
            self.checksum = 0
            self.urgentPointer = 0
            # TODO: options

        # TransportLayer::TCP
        def parse(self, stream, offset=0):
            self.sourcePort = int.from_bytes(stream[offset:offset+2], byteorder='big')
            self.destinationPort = int.from_bytes(stream[offset+2:offset+4], byteorder='big')
            self.sequenceNumber = int.from_bytes(stream[offset+4:offset+8], byteorder='big')
            self.acknowledgementNumber = int.from_bytes(stream[offset+8:offset:12], byteorder='big')
            self.headerLength = stream[offset+12] >> 4
            self.flags = int.from_bytes([(stream[offset+12] & 0x01), stream[offset+13]], byteorder='big')
            self.windowSize = int.from_bytes(stream[offset+14:offset+16], byteorder='big')
            self.checksum = int.from_bytes(stream[offset+16:offset+18], byteorder='big')
            self.urgentPointer = int.from_bytes(stream[offset+18:offset+20], byteorder='big')
            return True

        # TransportLayer::TCP
        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            message += f'{indentation}source port: {self.sourcePort},\n'
            message += f'{indentation}destination port: {self.destinationPort},\n'
            message += f'{indentation}sequence number: {self.sequenceNumber},\n'
            message += f'{indentation}acknowledgement number: {self.acknowledgementNumber},\n'
            message += f'{indentation}header length: {self.headerLength},\n'
            message += f'{indentation}flags: 0x{self.flags:02x},\n'
            message += f'{indentation}window size: {self.windowSize},\n'
            message += f'{indentation}checksum: 0x{self.checksum:04x},\n'
            message += f'{indentation}urgent pointer: {self.urgentPointer}\n'
            return message

        # TransportLayer::TCP
        def size(self):
            return self.headerLength * 4

        # TransportLayer::TCP
        def createContent(self):
            return None

    class UDP(Protocol):
        # TransportLayer::UDP
        def __init__(self):
            self.protocolName = 'user datagram protocol'

        # TransportLayer::UDP
        def parse(self, stream, offset=0):
            return True

        # TransportLayer::UDP
        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            return message

        # TransportLayer::UDP
        def size(self):
            return 0

        # TransportLayer::UDP
        def createContent(self):
            return None

    # TransportLayer
    def __init__(self, transporttype=TransportType.TRANSPORTTYPE_UNKNOWN):
        self.protocolName = 'transport'
        self.transportType = transporttype
        self.header = None
        self.content = None

    # TransportLayer
    def parse(self, stream, offset=0):
        # step 1. create header
        if self.transportType == TransportType.TRANSPORTTYPE_UDP:
            self.header = TransportLayer.UDP()
        elif self.transportType == TransportType.TRANSPORTTYPE_TCP:
            self.header = TransportLayer.TCP()

        if self.header == None:
            return false

        # step 2. set protocol name
        self.protocolName = self.header.protocolName

        # step 3. parse header
        self.header.parse(stream, offset)

        offset += self.header.size()

        # step 4. create content
        self.content = self.header.createContent()

        # step 5. parse content
        if self.content:
            self.content.parse(stream, offset)

        return True

    # TransportLayer
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

    # TransportLayer
    def size(self):
        return 0

