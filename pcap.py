import sys
import struct
from enum import *

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
            message = ''
            message += f'{indentation}magic: 0x{self.magic:08x},\n'
            message += f'{indentation}major: {self.major},\n'
            message += f'{indentation}minor: {self.minor},\n'
            message += f'{indentation}timezone: {self.timezone},\n'
            message += f'{indentation}significant figure: {self.significantFigure},\n'
            message += f'{indentation}snap length: {self.snapLength},\n'
            message += f'{indentation}link type: {self.linkType}\n'
            return message

        def size(self):
            return 4 + 2 + 2 + 4 + 4 + 4

    class Content:
        def __init__(self):
            self.packets = []

        def parse(self, file):
            self.packets = []

        def toString(self, indentationLevel=0):
            message = ''
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
