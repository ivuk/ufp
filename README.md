ufp
===

The Uncomplicated Firewall (ufw) log parser.

Usage: ufp.py [-h] [-p] [-s] [-src2dpt] [-dst2dpt] [-src2dst] [-ct] [-r] [-c]
              [-a] [-b] [-i] [-o] [-spt FILTER_SOURCE_PORT]
              [-dpt FILTER_DESTINATION_PORT] [-src FILTER_SOURCE_IP]
              [-dst FILTER_DESTINATION_IP]
              filename

positional arguments:
  filename              Specify which ufw log file to parse. - for stdin.
                        /var/log/ufw.log is default.

optional arguments:
  -h, --help            show this help message and exit
  -p, --print           Print the parsed data with a basic formatter which
                        displays source and destination pairs.
  -s, --summary         Print the parsed data with a summary which displays
                        distinct sources and destinations, ports.
  -src2dpt, --source-to-dst-port
                        Print the parsed data with a summary which displays
                        distinct sources and destination ports for each
                        source.
  -dst2dpt, --destination-to-dst-port
                        Print the parsed data with a summary which displays
                        distinct destinations and destination ports for each
                        destination.
  -src2dst, --source-to-dst
                        Print the parsed data with a summary which displays
                        distinct sources and destination addresses for each
                        source.
  -ct, --count          Count entries after filtering and display the number.
  -r, --reverse-dns     Enable reverse DNS lookupto translate IP addresses
                        into hostnames.
  -c, --colorize        Use colored icons in output to represent ALLOW or
                        BLOCK.
  -a, --filter-allow-only
                        Only display entries for which the resulting action
                        was ALLOW.
  -b, --filter-block-only
                        Only display entries for which the resulting action
                        was BLOCK.
  -i, --filter-inbound-only
                        Only display entries which were initiated inbound to
                        the logging host.
  -o, --filter-outbound-only
                        Only display entries which were initiated outbound
                        from the logging host.
  -spt FILTER_SOURCE_PORT, --filter-source-port FILTER_SOURCE_PORT
                        Only display entries which have a source port matching
                        the value provided.
  -dpt FILTER_DESTINATION_PORT, --filter-destination-port FILTER_DESTINATION_PORT
                        Only display entries which have a destination port
                        matching the value provided.
  -src FILTER_SOURCE_IP, --filter-source-ip FILTER_SOURCE_IP
                        Only display entries which have a source ip matching
                        the value provided.
  -dst FILTER_DESTINATION_IP, --filter-destination-ip FILTER_DESTINATION_IP
                        Only display entries which have a destination ip
                        matching the value provided.
                        
If no formatting arguments are provided, a table is printed along with
the count of matching entries (same as -p -ct).


Examples

-Only show traffic with a source of 8.8.4.4: ./ufp.py -src 8.8.4.4 tests/fixtures/ufw.log
-Only show allowed traffic with a destination port of 443: ./ufp.py -a -dpt 443 tests/fixtures/ufw.log
-Only show traffic inbound to the logging host which was blocked: ./ufp.py -i -b tests/fixtures/ufw.log
-Only show traffic inbound to the logging host which was blocked. Enable reverse DNS lookup for entries.: ./ufp.py -i -b -r tests/fixtures/ufw.log
