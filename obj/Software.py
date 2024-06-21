
class Software(object):
    society = ""
    software = ""
    version = []

    def __init__(self, software, version):
        self.software = software
        self.version = version

    def __str__(self):
        result = self.software + ':'
        for x in self.version:
            result += ' ' + x
        return result
