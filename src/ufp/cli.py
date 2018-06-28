from ufp.formatter.basic import BasicSrcDstActionFormatter
from ufp.formatter.count import CountFormatter
from ufp.parser.base import ParserFilter
from ufp.parser.file import FileParser
import argparse
from sys import stdin


class Cli():
    """
    Set up the available program options
    Call the right parsers and formatters depending on user input.
    """
    def __init__(self):
        arg_parser = argparse.ArgumentParser()

        arg_parser.add_argument('filename', metavar='filename',
                                default='/var/log/ufw.log',
                                type=str, nargs='?',
                                help='Specify which ufw log file to '
                                'parse. - for stdin. /var/log/ufw.log '
                                'is default.')

        arg_parser.add_argument('-p', '--print', action='store_true',
                                help='Print the parsed data with a '
                                'basic formatter which displays source '
                                'and destination pairs.')

        arg_parser.add_argument('-s', '--summary', action='store_true',
                                help='Print the parsed data with a '
                                'summary which displays distinct '
                                'sources and destinations, ports.')

        arg_parser.add_argument('-src2dpt', '--source-to-dst-port',
                                action='store_true', help='Print the'
                                'parsed data with a summary which '
                                'displays distinct sources and '
                                'destination ports for each source.')

        arg_parser.add_argument('-dst2dpt', '--destination-to-dst-port',
                                action='store_true', help='Print the '
                                'parsed data with a summary which '
                                'displays distinct destinations and '
                                'destination ports for each destination'
                                '.')

        arg_parser.add_argument('-src2dst', '--source-to-dst',
                                action='store_true',
                                help='Print the parsed data with a '
                                'summary which displays distinct '
                                'sources and destination addresses for '
                                'each source.')

        arg_parser.add_argument('-ct', '--count', action='store_true',
                                help='Count entries after filtering '
                                'and display the number.')

        arg_parser.add_argument('-r', '--reverse-dns',
                                action='store_true', help='Enable '
                                'reverse DNS lookup to translate IP '
                                'addresses into hostnames.')

        arg_parser.add_argument('-c', '--colorize', action='store_true',
                                help='Use colored icons in output to '
                                'represent ALLOW or BLOCK.')

        arg_parser.add_argument('-a', '--filter-allow-only',
                                action='store_true', help='Only '
                                'display entries for which the '
                                'resulting action was ALLOW.')

        arg_parser.add_argument('-b', '--filter-block-only',
                                action='store_true', help='Only '
                                'display entries for which the '
                                'resulting action was BLOCK.')

        arg_parser.add_argument('-i', '--filter-inbound-only',
                                action='store_true', help='Only '
                                'display entries which were '
                                'initiated inbound to the logging host.'
                                )

        arg_parser.add_argument('-o', '--filter-outbound-only',
                                action='store_true', help='Only '
                                'display entries which were '
                                'initiated outbound from the logging '
                                'host.')

        arg_parser.add_argument('-spt', '--filter-source-port',
                                action='store', help='Only display '
                                'entries which have a source port '
                                'matching the value provided.')

        arg_parser.add_argument('-dpt', '--filter-destination-port',
                                action='store', help='Only display '
                                'entries which have a destination port '
                                'matching the value provided.')

        arg_parser.add_argument('-src', '--filter-source-ip',
                                action='store', help='Only display '
                                'entries which have a source ip '
                                'matching the value provided.')

        arg_parser.add_argument('-dst', '--filter-destination-ip',
                                action='store', help='Only display '
                                'entries which have a destination ip '
                                'matching the value provided.')

        self.args = arg_parser.parse_args()

        filename = self.args.filename

        if filename == '-':
            # stdin
            fileobj = stdin
        else:
            fileobj = open(filename, 'r')

        log_parser = FileParser(fileobj)
        log_filter = ParserFilter(log_parser, self.args)

        entries = list(log_filter)

        self.formatters = []

        if self.args.print:
            formatter = BasicSrcDstActionFormatter(entries, self.args)
            self.formatters.append(formatter)

        if self.args.source_to_dst_port:
            from ufp.formatter.summary import SrcToDstPortFormatter
            formatter = SrcToDstPortFormatter(entries, self.args)
            self.formatters.append(formatter)

        if self.args.destination_to_dst_port:
            from ufp.formatter.summary import DstToDstPortFormatter
            formatter = DstToDstPortFormatter(entries, self.args)
            self.formatters.append(formatter)

        if self.args.source_to_dst:
            from ufp.formatter.summary import SrcToDstIPFormatter
            formatter = SrcToDstIPFormatter(entries, self.args)
            self.formatters.append(formatter)

        if self.args.count:
            formatter = CountFormatter(entries, self.args)
            self.formatters.append(formatter)

        if self.args.summary:
            from ufp.formatter.summary import SummaryFormatter
            formatter = SummaryFormatter(entries, self.args)
            self.formatters.append(formatter)

        if not self.args.print and not self.args.source_to_dst_port \
                and not self.args.destination_to_dst_port and not \
                self.args.source_to_dst and not self.args.count and not \
                self.args.summary:
            formatter = BasicSrcDstActionFormatter(entries, self.args)
            self.formatters.append(formatter)
            formatter = CountFormatter(entries, self.args)
            self.formatters.append(formatter)

    def execute(self):
        for formatter in self.formatters:
            formatter.format()
