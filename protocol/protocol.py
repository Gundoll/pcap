from abc import *

def makeIndentation(indentationLevel=0):
    indentation = ''
    for level in range(0, indentationLevel):
        indentation += '  '
    return indentation

class Protocol(metaclass=ABCMeta):
    def __init__(self):
        self.protocolName = 'unknown protocol'

    @abstractmethod
    def parse(stream, offset=0):
        return True

    @abstractmethod
    def toString(self, indentationLevel=0):
        return ''

    @abstractmethod
    def size(self):
        return 0
