import datetime
import re
import socket

class ParsedLine():
    ACTION_BLOCK = 0
    ACTION_ALLOW = 1

    _ip_protocol_table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}

    def __init__(self, data):
        self.data = data

    def get_protocol_name_by_id(self, protocol_id):
        return self._ip_protocol_table[int(protocol_id)]

    def get_proto(self):
        if self.proto.isdigit():
            return self.get_protocol_name_by_id(self.proto)
        return self.proto

    def ip_to_hostname(self, addr):
        try:
            return socket.gethostbyaddr(addr)[0]
        except socket.herror:
            return None

    def set_action(self, action):
        if action == 'ALLOW':
            self.action = self.ACTION_ALLOW
        elif action == 'BLOCK':
            self.action = self.ACTION_BLOCK
        else:
            raise ValueError("action must be ALLOW or BLOCK")

    def allowed(self):
        return self.action == self.ACTION_ALLOW

    def blocked(self):
        return self.action == self.ACTION_BLOCK

    def inbound(self):
        return self.data['IN'] != ''

    def outbound(self):
        return self.data['OUT'] != ''

    def get_action_text(self):
        if self.action == self.ACTION_ALLOW:
            return 'ALLOW'
        return 'BLOCK'

    def __getattr__(self, name):
        name = name.upper()

        try:
            value = self.data[name]
        except KeyError:
            if name == "SPT" or name == "DPT":
                return '-'
            return None

        if name == "SPT" or name == "DPT":
            return int(value)

        return value

    def __repr__(self):
        keys = sorted(self.__dict__)
        items = ("{}={!r}".format(k, self.__dict__[k]) for k in keys)
        return "{}({})".format(type(self).__name__, ", ".join(items))

class BaseParser():
    # Aug  6 06:25:20 myhost kernel: [105600.181847] [UFW ALLOW] ...
    HEADER_PATTERN = r'([A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) ([a-zA-Z0-9-]+) kernel: \[.*\] \[UFW ([A-Z]+)\]'
    # IN= OUT=eno1 SRC=123.45.67.89 DST=123.45.67.88 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=24678 DF PROTO=TCP SPT=37314 DPT=11211 WINDOW=29200 RES=0x00 SYN URGP=0
    PARAM_PATTERN = r'(\w+)[=]?([\w.:]*)'

    def __init__(self):
        self.header_regex = re.compile(self.HEADER_PATTERN)
        self.param_regex = re.compile(self.PARAM_PATTERN)

    def parse_line(self, line):
        # parse header
        header_groups = self.header_regex.findall(line)
        # convert date to python object
        date = datetime.datetime.strptime(header_groups[0][0], '%b %d %H:%M:%S')

        # was the connection attempt ALLOWed or BLOCKed?
        action = header_groups[0][2]
        # get the rest of the line
        remainder = self.header_regex.sub('', line)
        # parse and convert to key/value pairs
        param_groups = self.param_regex.findall(remainder)
        data = dict(param_groups)
        # add in header data
        data['DATE'] = date

        parsed_line = ParsedLine(data)
        parsed_line.set_action(action)

        return parsed_line

class ParserFilter():
    """
    Filters data from a parser on __iter__ such as when looped or
    evaluated as a list.
    """

    def __init__(self, parser, filters):
        # avoid calling __setattr__
        self.__dict__['parser'] = parser
        self.__dict__['options'] = filters

    def __setattr__(self, name, value):
        setattr(self.__dict__['options'], name, value)

    def filter_line(self, parsed_line):
        if self.options.filter_allow_only and parsed_line.blocked():
            return False
        if self.options.filter_block_only and parsed_line.allowed():
            return False
        if self.options.filter_inbound_only and parsed_line.outbound():
            return False
        if self.options.filter_outbound_only and parsed_line.inbound():
            return False
        if self.options.filter_source_port and \
            parsed_line.spt != int(self.options.filter_source_port):
            return False
        if self.options.filter_destination_port and \
            parsed_line.dpt != int(self.options.filter_destination_port):
            return False
        if self.options.filter_source_ip and \
            parsed_line.src != self.options.filter_source_ip:
            return False
        if self.options.filter_destination_ip and \
            parsed_line.dst != self.options.filter_destination_ip:
            return False

        return True

    def __iter__(self):
        return filter(self.filter_line, self.parser)
