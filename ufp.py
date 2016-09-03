#!/usr/bin/env python


import argparse
import os
import socket
import sys


def CheckFile(FileName):
    """
    Check if the file that we should parse is a file and if we can read it
    """
    if not os.path.isfile(FileName) and not os.access(FileName, os.R_OK):
        print "File '%s' is not a file or cannot be read." % FileName
        sys.exit(14)

def LookupIP(addr):
    try:
        return socket.gethostbyaddr(addr)[0]
    except socket.herror:
        return None

def PairSrcIPsAndDstPorts(FileName, DoIPLookup):
    """
    Pair source IP addresses and ports they tried to connect to
    """
    SrcIPsAndDstPorts = dict()

    with open(FileName) as FN:
        for line in FN:
            SrcIP = line[line.find('SRC'):line.find('DST')][4:-1]

            if SrcIP not in SrcIPsAndDstPorts.keys():
                SrcIPsAndDstPorts[SrcIP] = []

            if 'DPT' in line:
                line = line[line.find('DPT'):]
                if 'LEN' in line:
                    DstPort = line[line.find('DPT'):line.find('LEN')][4:-1]
                elif 'WINDOW' in line:
                    DstPort = line[line.find('DPT'):line.find('WINDOW')][4:-1]

                if DstPort not in SrcIPsAndDstPorts[SrcIP]:
                    CurPortList = list(SrcIPsAndDstPorts[SrcIP])
                    CurPortList.append(DstPort)
                    SrcIPsAndDstPorts[SrcIP] = CurPortList

    print "Source IP/MAC\tDestination port(s)"
    for SrcIP in SrcIPsAndDstPorts.keys():
        print "%s\t%s" % (SrcIP, ', '.join(SrcIPsAndDstPorts[SrcIP]))


def PairDstIPsAndSrcIPs(FileName, DoIPLookup):
    """
    Pair destination and source IP addresses
    """
    DstIPsAndSrcIPs = dict()
    DstHosts = {}
    SrcHosts = {}

    with open(FileName) as FN:
        for line in FN:
            DstIP = line[line.find('DST'):line.find('LEN')][4:-1]

            if DoIPLookup == True:
                if DstIP not in DstHosts:
                    DstHosts[DstIP] = LookupIP(DstIP)

            if DstIP not in DstIPsAndSrcIPs.keys():
                DstIPsAndSrcIPs[DstIP] = []

            SrcIP = line[line.find('SRC'):line.find('DST')][4:-1]

            if DoIPLookup == True:
                if SrcIP not in SrcHosts:
                    SrcHosts[SrcIP] = LookupIP(SrcIP)

            if SrcIP not in DstIPsAndSrcIPs[DstIP]:
                    CurSourceIPList = list(DstIPsAndSrcIPs[DstIP])
                    CurSourceIPList.append(SrcIP)
                    DstIPsAndSrcIPs[DstIP] = CurSourceIPList


    print "Destination IP/MAC\tSource IP/MAC"
    for DstIP in DstIPsAndSrcIPs.keys():
        if DoIPLookup == True:
            print "%s (%s)\t\t%s" % (DstIP, DstHosts[DstIP], ', '.join(DstIPsAndSrcIPs[DstIP]))
        else:
            print "%s\t\t%s" % (DstIP, ', '.join(DstIPsAndSrcIPs[DstIP]))

def PrintDstIPsAndDstPorts(FileName, DoIPLookup):
    """
    Print destination IP addresses and ports
    """
    DstIPsAndDstPorts = {}
    DstHosts = {}

    with open(FileName) as FN:
        for line in FN:
            DstIP = line[line.find('DST'):line.find('LEN')][4:-1]

            if DoIPLookup == True:
                if DstIP not in DstHosts:
                    DstHosts[DstIP] = LookupIP(DstIP)

            if DstIP not in DstIPsAndDstPorts.keys():
                DstIPsAndDstPorts[DstIP] = []

            if 'DPT' in line:
                line = line[line.find('DPT'):]
                if 'LEN' in line:
                    DstPort = line[line.find('DPT'):line.find('LEN')][4:-1]
                elif 'WINDOW' in line:
                    DstPort = line[line.find('DPT'):line.find('WINDOW')][4:-1]

                if DstPort not in DstIPsAndDstPorts[DstIP]:
                    CurPortList = list(DstIPsAndDstPorts[DstIP])
                    CurPortList.append(DstPort)
                    DstIPsAndDstPorts[DstIP] = CurPortList

    print "Destination IP/MAC\tSource IP/MAC"
    for DstIP in DstIPsAndDstPorts.keys():
        if DoIPLookup == True:
            print "{dsthost:75} [{dstip:39}] {dstports}" \
            .format(dsthost=DstHosts[DstIP], dstip=DstIP, dstports=', '.join(DstIPsAndDstPorts[DstIP]))
        else:
            print "%s\t\t%s" % (DstIP, ', '.join(DstIPsAndDstPorts[DstIP]))


def ParseLog(FileName, DoIPLookup):
    """
    Function for parsing the log file
    """
    SrcIPs = set()
    DstIPs = set()
    SrcPorts = set()
    DstPorts = set()

    SrcHosts = {}
    DstHosts = {}

    with open(FileName) as FN:
        for line in FN:
            SrcIP = line[line.find('SRC'):line.find('DST')][4:-1]
            SrcIPs.add(SrcIP)
            DstIP = line[line.find('DST'):line.find('LEN')][4:-1]
            DstIPs.add(DstIP)

            if DoIPLookup == True:
                if not SrcIP in SrcHosts:
                    SrcHosts[SrcIP] = LookupIP(SrcIP)
                if not DstIP in DstHosts:
                    DstHosts[DstIP] = LookupIP(DstIP)

            if 'SPT' in line:
                SrcPorts.add(line[line.find('SPT'):line.find('DPT')][4:-1])

            if 'DPT' in line:
                line = line[line.find('DPT'):]
                if 'LEN' in line:
                    DstPorts.add(line[line.find('DPT'):line.find('LEN')]
                                 [4:-1])
                elif 'WINDOW' in line:
                    DstPorts.add(line[line.find('DPT'):line.find('WINDOW')]
                                 [4:-1])

    ShowOut(SrcIPs, DstIPs, SrcPorts, DstPorts, SrcHosts, DstHosts)


def ShowOut(SrcIPs, DstIPs, SrcPorts, DstPorts, SrcHosts, DstHosts):
    """
    Function for printing out the gathered info
    """
    print 'Source IP/MAC addresses: ' + ', '.join(SrcIPs)
    print 'Destination IP/MAC addresses: ' + ', '.join(DstIPs)
    print 'Source ports: ' + ', '.join(SrcPorts)
    print 'Destination ports: ' + ', '.join(DstPorts)
    print 'Source Hostnames: ' + ', '.join(['[%s] %s' % (key, value) for (key, value) in SrcHosts.items()])
    print 'Destination Hostnames: ' + ', '.join(['[%s] %s' % (key, value) for (key, value) in DstHosts.items()])


def DoIt():
    """
    Set up the available program options
    Call the proper functions with proper parameters depending on user
    input
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', dest='FileName', help='Specify which \
                        ufw log file to parse', default='/var/log/ufw.log',
                        type=str, action='store')
    parser.add_argument('-s', '--source', dest='MatchSourceAndPort',
                        action='store_true', help='Show which IP tried to \
                                connect to which port')
    parser.add_argument('-b', '--brief', dest='ParseLogBrief',
                        action='store_true', help='Show a short summary of \
                        data in the log file')
    parser.add_argument('-d', '--dest', dest='MatchDestIPAndSrcIP',
                        action='store_true', help='Show which source IP \
                        tried to connect to which destination IP')
    parser.add_argument('-p', '--dest-ports', dest='PrintDstIPAndDstPorts',
                        action='store_true', help='Show destination IPs \
                        and associated destination ports')
    parser.add_argument('-r', '--reverse-dns', dest='DoIPLookup', action='store_true', \
                        help='Perform reverse lookup of IP addresses to hostnames')

    args = parser.parse_args()

    if not (args.ParseLogBrief or args.MatchSourceAndPort or
            args.MatchDestIPAndSrcIP or args.PrintDstIPAndDstPorts):
        parser.print_help()

    if args.FileName:
        CheckFile(args.FileName)
    if args.ParseLogBrief:
        CheckFile(args.FileName)
        ParseLog(args.FileName, args.DoIPLookup)
    if args.MatchSourceAndPort:
        CheckFile(args.FileName)
        PairSrcIPsAndDstPorts(args.FileName, args.DoIPLookup)
    if args.MatchDestIPAndSrcIP:
        CheckFile(args.FileName)
        PairDstIPsAndSrcIPs(args.FileName, args.DoIPLookup)
    if args.PrintDstIPAndDstPorts:
        CheckFile(args.FileName)
        PrintDstIPsAndDstPorts(args.FileName, args.DoIPLookup)


if __name__ == "__main__":
    DoIt()
