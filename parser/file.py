from .base import BaseParser

class FileParser(BaseParser):
    """
    A parser which accepts a filename and allows iteration to retrieve
    ParsedLine instances.
    """
    def __init__(self, filename):
        self.file = open(filename, 'r')
        super().__init__()
        
    def __iter__(self):
        return self
        
    def __next__(self):
        line = self.file.readline()
        
        if line != '':
            return self.parse_line(line)
        else:
            raise StopIteration
