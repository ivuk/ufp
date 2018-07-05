from .base import BaseFormatter


class SummaryFormatter(BaseFormatter):
    """
    Formatter which displays source and destination pairs.
    """
    def aggregate(self):
        self.src_ips = set()
        self.dst_ips = set()
        self.src_ports = set()
        self.dst_ports = set()

        self.src_hosts = {}
        self.dst_hosts = {}

        self.start_datetime = None
        self.end_datetime = None

        for line in self.entries:
            if self.start_datetime is None:
                self.start_datetime = line.date

            self.end_datetime = line.date

            self.src_ips.add(line.src)
            self.dst_ips.add(line.dst)

            if self.options.reverse_dns:
                if line.src not in self.src_hosts:
                    self.src_hosts[line.src] = line.ip_to_hostname(line.src)
                if line.dst not in self.dst_hosts:
                    self.dst_hosts[line.dst] = line.ip_to_hostname(line.dst)

            spt = line.spt
            if spt is not None:
                self.src_ports.add(spt)

            dpt = line.dpt
            if dpt is not None:
                self.dst_ports.add(dpt)

    def format(self):
        self.aggregate()
        if self.start_datetime and self.end_datetime:
            print('Log start/end: ' + self.start_datetime.strftime('%c')
                  + '/' + self.end_datetime.strftime('%c') + '\n\n')
        print('Source IP/MAC addresses: ' + ', '.join(sorted(self.src_ips))
              + '\n\n')
        print('Destination IP/MAC addresses: '
              + ', '.join(sorted(self.dst_ips))
              + '\n\n')
        print('Source ports: ' + ', '.join([str(value) for value in
              sorted(self.src_ports)]) + '\n\n')
        print('Destination ports: ' + ', '.join([str(value) for value
              in sorted(self.dst_ports)]) + '\n\n')
        if self.options.reverse_dns:
            print('Source Hostnames: ' + ', '.join(['[%s] %s' %
                  (key, value) for (key, value) in
                  self.src_hosts.items()]) + '\n\n')
            print('Destination Hostnames: ' + ', '.join(['[%s] %s' %
                  (key, value) for (key, value) in
                  self.dst_hosts.items()]) + '\n\n')


class SrcToDstPortFormatter(BaseFormatter):
    """
    Pair source IP addresses and ports they tried to connect to
    """
    def aggregate(self):
        self.dst_ports_by_src_ip = dict()

        for line in self.entries:
            if line.src not in self.dst_ports_by_src_ip.keys():
                self.dst_ports_by_src_ip[line.src] = []

            dpt = line.dpt
            if dpt and dpt not in self.dst_ports_by_src_ip[line.src]:
                ports = list(self.dst_ports_by_src_ip[line.src])
                ports.append(dpt)
                self.dst_ports_by_src_ip[line.src] = ports

    def format(self):
        self.aggregate()
        print("Source IP\tDestination port(s)\n")
        for src in sorted(self.dst_ports_by_src_ip.keys()):
            print("%s\t%s" % (src, ', '.join([str(value) for value in
                  sorted(self.dst_ports_by_src_ip[src])])))


class DstToDstPortFormatter(BaseFormatter):
    """
    Pair destination IP addresses and ports they tried to connect to
    """
    def aggregate(self):
        self.dst_ports_by_dst_ip = dict()

        for line in self.entries:
            if line.dst not in self.dst_ports_by_dst_ip.keys():
                self.dst_ports_by_dst_ip[line.dst] = []

            dpt = line.dpt
            if dpt and dpt not in self.dst_ports_by_dst_ip[line.dst]:
                ports = list(self.dst_ports_by_dst_ip[line.dst])
                ports.append(dpt)
                self.dst_ports_by_dst_ip[line.dst] = ports

    def format(self):
        self.aggregate()
        print("Destination IP\tDestination port(s)\n")
        for dst in sorted(self.dst_ports_by_dst_ip.keys()):
            if self.options.reverse_dns:
                print("{dsthost:75} [{dstip:39}] {dstports}"
                      .format(dsthost=self.hosts[dst], dstip=dst,
                              dstports=', '.join(
                              self.dst_ports_by_dst_ip[dst])))
            else:
                print("%s\t\t%s" % (dst, ', '.join([str(value) for
                      value in sorted(self.dst_ports_by_dst_ip[dst])])))


class SrcToDstIPFormatter(BaseFormatter):
    """
    Pair source IP addresses and destination IP addresses they tried to
    connect to
    """
    def aggregate(self):
        self.src_ips_by_dst_ip = dict()

        for line in self.entries:
            if line.dst not in self.src_ips_by_dst_ip.keys():
                self.src_ips_by_dst_ip[line.dst] = []

            src = line.src
            if src and src not in self.src_ips_by_dst_ip[line.dst]:
                source_ips = list(self.src_ips_by_dst_ip[line.dst])
                source_ips.append(src)
                self.src_ips_by_dst_ip[line.dst] = source_ips

    def format(self):
        self.aggregate()
        print("Destination IP\tSource IP")
        for dst in sorted(self.src_ips_by_dst_ip.keys()):
            if self.options.reverse_dns:
                print("%s (%s)\t\t%s" % (dst, self.hosts[dst],
                      ', '.join([str(value) for value in
                                sorted(self.src_ips_by_dst_ip[dst])])))
            else:
                print("%s\t%s" % (dst, ', '.join([str(value) for value
                      in sorted(self.src_ips_by_dst_ip[dst])])))
