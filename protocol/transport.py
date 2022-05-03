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

        # TransportLayer::TCP
        def parse(self, stream, offset=0):
            return True

        # TransportLayer::TCP
        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            return message

        # TransportLayer::TCP
        def size(self):
            return 0

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

