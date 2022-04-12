import sys
import struct
from protocol.link import *

def makeIndentation(indentationLevel):
    indentation = ''
    for idx in range(indentationLevel):
        indentation += '\t'
    return indentation

class Pcap:
    class Header:
        def __init__(self):
            self.magic = 0
            self.major = 0
            self.minor = 0
            self.timezone = 0
            self.timestamp = 0
            self.significantFigure = 0
            self.snapLength = 0
            self.linkType = 0

        def parse(self, file):
            file.seek(0)

            self.magic = int.from_bytes(file.read(4), byteorder=sys.byteorder)
            self.major = int.from_bytes(file.read(2), byteorder=sys.byteorder)
            self.minor = int.from_bytes(file.read(2), byteorder=sys.byteorder)
            self.timezone = int.from_bytes(file.read(4), byteorder=sys.byteorder)
            self.significantFigure = int.from_bytes(file.read(4), byteorder=sys.byteorder)
            self.snapLength = int.from_bytes(file.read(4), byteorder=sys.byteorder)
            self.linkType = int.from_bytes(file.read(4), byteorder=sys.byteorder)

        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            linktypeName = ''
            try:
                linktypeName = LinkType(self.linkType).name
            except:
                linktypeName = 'UNSUPPORTED LINKTYPE'
            message = ''
            message += f'{indentation}magic: 0x{self.magic:08x},\n'
            message += f'{indentation}major: {self.major},\n'
            message += f'{indentation}minor: {self.minor},\n'
            message += f'{indentation}timezone: {self.timezone},\n'
            message += f'{indentation}significant figure: {self.significantFigure},\n'
            message += f'{indentation}snap length: {self.snapLength},\n'
            message += f'{indentation}link type: {self.linkType}({linktypeName})\n'
            return message

        def size(self):
            return 4 + 2 + 2 + 4 + 4 + 4

    class Packet:
        class Header:
            def __init__(self):
                self.timestampSec = 0
                self.timestampUSec = 0
                self.captureLength = 0 # number of octets of packet saved in file
                self.packetLength = 0 # actural length of the packet

            def parse(self, stream, offset=0):
                self.timestampSec = int.from_bytes(stream[offset:offset+4], byteorder=sys.byteorder)
                self.timestampUSec = int.from_bytes(stream[offset+4:offset+8], byteorder=sys.byteorder)
                self.captureLength = int.from_bytes(stream[offset+8:offset+12], byteorder=sys.byteorder)
                self.packetLength = int.from_bytes(stream[offset+12:offset+16], byteorder=sys.byteorder)

            def toString(self, indentationLevel=0):
                indentation = makeIndentation(indentationLevel)
                message = ''
                message += f'{indentation}timestamp(seconds): {self.timestampSec},\n'
                message += f'{indentation}timestamp(micro-seconds): {self.timestampUSec},\n'
                message += f'{indentation}capture length: {self.captureLength},\n'
                message += f'{indentation}packet length: {self.packetLength}\n'
                return message

            def size(self):
                return 4 + 4 + 4 + 4

        class Content:
            def __init__(self):
                self.link = None

            def parse(self, stream, offset=0):
                # TODO: parse LinkLayer
                return True

            def toString(self, indentationLevel=0):
                indentation = makeIndentation(indentationLevel)
                message = ''
                return message

        def __init__(self):
            self.header = Pcap.Packet.Header()
            self.content = Pcap.Packet.Content()

        def parse(self, file):
            stream = file.read(16)
            if not stream:
                return False

            self.header.parse(stream)

            stream = file.read(self.header.packetLength)
            self.content.parse(stream)
            return True

        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            message += f'{indentation}header: {{\n'
            message += f'{self.header.toString(indentationLevel+1)}'
            message += f'{indentation}}},\n'
            message += f'{indentation}content: {{\n'
            message += f'{self.content.toString(indentationLevel+1)}'
            message += f'{indentation}}}\n'
            return message

        def size(self):
            return self.header.size + self.header.packetLength

    class Content:
        def __init__(self):
            self.packets = []

        def parse(self, file):
            packet = Pcap.Packet()
            while packet.parse(file):
                self.packets.append(packet)
                packet = Pcap.Packet()

        def toString(self, indentationLevel=0):
            indentation = makeIndentation(indentationLevel)
            message = ''
            for idx, packet in enumerate(self.packets):
                message += f'{indentation}packet[{idx}]: {{\n'
                message += f'{packet.toString(indentationLevel+1)}'
                message += f'{indentation}}}'
                if idx != len(self.packets)-1:
                    message += ','
                message += '\n'
            return message

    def __init__(self, filename):
        self.header = Pcap.Header()
        self.content = Pcap.Content()
        self.filename = filename

    def parse(self):
        file = open(self.filename, 'rb')
        self.header.parse(file)
        self.content.parse(file)
        file.close()

    def toString(self, indentationLevel=0):
        indentation = makeIndentation(indentationLevel)
        message = f'{indentation}header: {{\n'
        message += self.header.toString(indentationLevel+1)
        message += f'{indentation}}},\n{indentation}content: {{\n'
        message += self.content.toString(indentationLevel+1)
        message += f'{indentation}}}\n'
        return message

if __name__=='__main__':
    pcapSeq = []
    for idx in range(1, len(sys.argv)):
        pcapSeq.append(Pcap(sys.argv[idx]))

    for idx, pcap in enumerate(pcapSeq):
        pcap.parse()
        print(f'file[{idx}]: {pcap.filename}\n{pcap.toString(1)}')
