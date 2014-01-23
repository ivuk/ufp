#!/usr/bin/env python


import argparse
import os
import sys


def CheckFile(FileName):
    """
    Check if the file that we should parse is a file and if we can read it
    """
    if not os.path.isfile(FileName) and not os.access(FileName, os.R_OK):
        print "File '%s' is not a file or cannot be read." % FileName
        sys.exit(14)


def PairSrcIPsAndDstPorts(FileName):
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


def PairDstIPsAndSrcIPs(FileName):
    """
    Pair destination and source IP addresses
    """
    DstIPsAndSrcIPs = dict()

    with open(FileName) as FN:
        for line in FN:
            DstIP = line[line.find('DST'):line.find('LEN')][4:-1]

            if DstIP not in DstIPsAndSrcIPs.keys():
                DstIPsAndSrcIPs[DstIP] = []

            SrcIP = line[line.find('SRC'):line.find('DST')][4:-1]

            if SrcIP not in DstIPsAndSrcIPs[DstIP]:
                    CurSourceIPList = list(DstIPsAndSrcIPs[DstIP])
                    CurSourceIPList.append(SrcIP)
                    DstIPsAndSrcIPs[DstIP] = CurSourceIPList

    print "Destination IP/MAC\tSource IP/MAC"
    for DstIP in DstIPsAndSrcIPs.keys():
        print "%s\t\t%s" % (DstIP, ', '.join(DstIPsAndSrcIPs[DstIP]))


def ParseLog(FileName):
    """
    Function for parsing the log file
    """
    SrcIPs = set()
    DstIPs = set()
    SrcPorts = set()
    DstPorts = set()

    with open(FileName) as FN:
        for line in FN:
            SrcIPs.add(line[line.find('SRC'):line.find('DST')][4:-1])
            DstIPs.add(line[line.find('DST'):line.find('LEN')][4:-1])

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

    ShowOut(SrcIPs, DstIPs, SrcPorts, DstPorts)


def ShowOut(SrcIPs, DstIPs, SrcPorts, DstPorts):
    """
    Function for printing out the gathered info
    """
    print 'Source IP/MAC addresses: ' + ', '.join(SrcIPs)
    print 'Destination IP/MAC addresses: ' + ', '.join(DstIPs)
    print 'Source ports: ' + ', '.join(SrcPorts)
    print 'Destination ports: ' + ', '.join(DstPorts)


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

    args = parser.parse_args()

    if not (args.ParseLogBrief or args.MatchSourceAndPort or
            args.MatchDestIPAndSrcIP):
        parser.print_help()

    if args.FileName:
        CheckFile(args.FileName)
    if args.ParseLogBrief:
        CheckFile(args.FileName)
        ParseLog(args.FileName)
    if args.MatchSourceAndPort:
        CheckFile(args.FileName)
        PairSrcIPsAndDstPorts(args.FileName)
    if args.MatchDestIPAndSrcIP:
        CheckFile(args.FileName)
        PairDstIPsAndSrcIPs(args.FileName)


if __name__ == "__main__":
    DoIt()
