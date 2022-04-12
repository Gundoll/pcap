from abc import *

def makeIndentation(indentationLevel):
    indentation = ''
    for idx in range(indentationLevel):
        indentation += '\t'
    return indentation

class Protocol(metaclass=ABCMeta):
    def __init__(self):
        self.protocolName = 'unknown protocol'

    @abstractmethod
    def parse(self, stream, offset=0):
        return True

    @abstractmethod
    def toString(self, indentationLevel=0):
        return ''

    @abstractmethod
    def size(self):
        return 0

