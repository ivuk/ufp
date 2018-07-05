import os
import sys
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../../src/')

from ufp.parser.base import BaseParser, ParsedLine, ParserFilter  # nopep8
import datetime  # nopep8
from types import SimpleNamespace  # nopep8
import pytest  # nopep8


@pytest.fixture
def log_line():
    return "Aug  6 06:25:20 myhost kernel: [105600.181847] [UFW ALLOW] \
IN= OUT=eno1 SRC=123.45.67.89 DST=123.45.67.88 LEN=60 TOS=0x00 \
PREC=0x00 TTL=64 ID=24678 DF PROTO=TCP SPT=37314 DPT=11211 \
WINDOW=29200 RES=0x00 SYN URGP=0"


@pytest.fixture
def log_audit_line():
    return "Aug  6 06:25:20 myhost kernel: [105600.181847] [UFW AUDIT] \
IN= OUT=eno1 SRC=123.45.67.89 DST=123.45.67.88 LEN=60 TOS=0x00 \
PREC=0x00 TTL=64 ID=24678 DF PROTO=TCP SPT=37314 DPT=11211 \
WINDOW=29200 RES=0x00 SYN URGP=0"


@pytest.fixture
def log_line_multicast():
    return "Aug  6 06:27:10 myhost kernel: [105709.694155] [UFW BLOCK] \
IN=eno1 OUT= MAC=01:00:5e:00:00:01:e8:de:27:25:a8:3e:08:00 \
SRC=192.168.0.1 DST=224.0.0.1 LEN=32 TOS=0x1C PREC=0xC0 TTL=1 ID=0 \
PROTO=2"


@pytest.fixture
def log_lines():
    return [
        "Aug  6 06:25:20 myhost kernel: [105600.181847] [UFW ALLOW] \
IN= OUT=eno1 SRC=123.45.67.89 DST=123.45.67.88 LEN=60 TOS=0x00 \
PREC=0x00 TTL=64 ID=24678 DF PROTO=TCP SPT=37314 DPT=11211 \
WINDOW=29200 RES=0x00 SYN URGP=0",
        "Aug  6 06:25:21 myhost kernel: [105600.181923] [UFW ALLOW] \
IN=eno1 OUT= SRC=123.45.67.88 DST=123.45.67.89 LEN=60 TOS=0x00 \
PREC=0x00 TTL=64 ID=24679 DF PROTO=TCP SPT=11211 DPT=37314 \
WINDOW=29200 RES=0x00 SYN URGP=0",
        "Aug  6 06:25:21 myhost kernel: [105600.181946] [UFW BLOCK] \
IN=eno1 OUT= SRC=123.45.67.88 DST=123.45.67.89 LEN=60 TOS=0x00 \
PREC=0x00 TTL=64 ID=24680 DF PROTO=TCP SPT=11211 DPT=37314 \
WINDOW=29200 RES=0x00 SYN URGP=0",
        "Aug  6 06:27:10 myhost kernel: [105709.694155] [UFW BLOCK] \
IN=eno1 OUT= MAC=01:00:5e:00:00:01:e8:de:27:25:a8:3e:08:00 \
SRC=192.168.0.1 DST=224.0.0.1 LEN=32 TOS=0x1C PREC=0xC0 TTL=1 ID=0 \
PROTO=2",
    ]


@pytest.fixture
def parsed_line(log_line):
    parser = BaseParser()
    return parser.parse_line(log_line)

# BaseParser


def test_parse_line_returns_parsed_line(parsed_line):
    assert isinstance(parsed_line, ParsedLine)


def test_parse_line_returns_parsed_line_with_date(parsed_line):
    expected_datetime = datetime.datetime.strptime('Aug 6 06:25:20',
                                                   '%b %d %H:%M:%S')

    assert parsed_line.date == expected_datetime


def test_parse_line_returns_parsed_line_with_action(parsed_line):
    assert parsed_line.action == ParsedLine.ACTION_ALLOW


def test_parse_line_returns_parsed_line_with_audit_action(log_audit_line):
    parser = BaseParser()
    parsed_line = parser.parse_line(log_audit_line)
    assert parsed_line.action is None


def test_parse_line_returns_parsed_line_with_empty_in(parsed_line):
    # use CAPS version to avoid Python reserved word
    assert parsed_line.IN == ''


def test_parse_line_returns_parsed_line_with_out(parsed_line):
    assert parsed_line.out == 'eno1'


def test_parse_line_returns_parsed_line_with_src(parsed_line):
    assert parsed_line.src == '123.45.67.89'


def test_parse_line_returns_parsed_line_with_dst(parsed_line):
    assert parsed_line.dst == '123.45.67.88'


def test_parse_line_returns_parsed_line_with_len(parsed_line):
    assert parsed_line.len == '60'


def test_parse_line_returns_parsed_line_with_tos(parsed_line):
    assert parsed_line.tos == '0x00'


def test_parse_line_returns_parsed_line_with_tos(parsed_line):
    assert parsed_line.prec == '0x00'


def test_parse_line_returns_parsed_line_with_ttl(parsed_line):
    assert parsed_line.ttl == '64'


def test_parse_line_returns_parsed_line_with_tos(parsed_line):
    assert parsed_line.prec == '0x00'


def test_parse_line_returns_parsed_line_with_id(parsed_line):
    assert parsed_line.id == '24678'


def test_parse_line_returns_parsed_line_with_df(parsed_line):
    assert parsed_line.df == ''


def test_parse_line_returns_parsed_line_with_proto(parsed_line):
    assert parsed_line.proto == 'TCP'


def test_parse_line_returns_parsed_line_with_spt(parsed_line):
    # ports are converted to int for correct sorting behavior
    assert parsed_line.spt == 37314


def test_parse_line_returns_parsed_line_with_dpt(parsed_line):
    # ports are converted to int for correct sorting behavior
    assert parsed_line.dpt == 11211


def test_parse_line_returns_parsed_line_with_window(parsed_line):
    assert parsed_line.window == '29200'


def test_parse_line_returns_parsed_line_with_res(parsed_line):
    assert parsed_line.res == '0x00'


def test_parse_line_returns_parsed_line_with_syn(parsed_line):
    assert parsed_line.syn == ''


def test_parse_line_returns_parsed_line_with_urgp(parsed_line):
    assert parsed_line.urgp == '0'

# ParsedLine


def test_parsed_line_allowed(parsed_line):
    assert parsed_line.allowed()


def test_parsed_line_blocked(parsed_line):
    assert not parsed_line.blocked()


def test_parsed_line_inbound(parsed_line):
    assert not parsed_line.inbound()


def test_parsed_line_outbound(parsed_line):
    assert parsed_line.outbound()


def test_parsed_get_action_text(parsed_line):
    assert parsed_line.get_action_text() == 'ALLOW'

# ParserFilter


@pytest.fixture
def parser_filter(log_lines):
    parser = BaseParser()
    parsed_lines = []
    for line in log_lines:
        parsed_lines.append(parser.parse_line(line))

    # initialize all filters to False
    filters = SimpleNamespace()
    filters.filter_allow_only = False
    filters.filter_block_only = False
    filters.filter_inbound_only = False
    filters.filter_outbound_only = False
    filters.filter_source_port = False
    filters.filter_source_ip = False
    filters.filter_destination_port = False
    filters.filter_destination_ip = False

    return ParserFilter(parsed_lines, filters)


def test_filter_allow_only(parser_filter):
    parser_filter.filter_allow_only = True

    for parsed_line in parser_filter:
        assert parsed_line.allowed()


def test_filter_block_only(parser_filter):
    parser_filter.filter_block_only = True

    for parsed_line in parser_filter:
        assert parsed_line.blocked()


def test_filter_inbound_only(parser_filter):
    parser_filter.filter_inbound_only = True

    for parsed_line in parser_filter:
        assert parsed_line.inbound()


def test_filter_outbound_only(parser_filter):
    parser_filter.filter_outbound_only = True

    for parsed_line in parser_filter:
        assert parsed_line.outbound()


def test_filter_source_port(parser_filter):
    parser_filter.filter_source_port = 37314

    for parsed_line in parser_filter:
        assert parsed_line.spt == 37314


def test_filter_destination_port(parser_filter):
    parser_filter.filter_destination_port = 11211

    for parsed_line in parser_filter:
        assert parsed_line.dpt == 11211


def test_filter_source_ip(parser_filter):
    parser_filter.filter_source_ip = '123.45.67.88'

    for parsed_line in parser_filter:
        assert parsed_line.src == '123.45.67.88'


def test_filter_destination_ip(parser_filter):
    parser_filter.filter_destination_ip = '224.0.0.1'

    for parsed_line in parser_filter:
        assert parsed_line.dst == '224.0.0.1'
