#!/usr/bin/env python


import os
import argparse


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
                    DstPorts.add(line[line.find('DPT'):line.find('LEN')][4:-1])
                elif 'WINDOW' in line:
                    DstPorts.add(line[line.find('DPT'):line.find('WINDOW')]
                                 [4:-1])

    ShowOut(SrcIPs, DstIPs, SrcPorts, DstPorts)


def ShowOut(SrcIPs, DstIPs, SrcPorts, DstPorts):
    """
    Function for printing out the gathered info
    """
    print 'Source IP addresses: ' + ', '.join(SrcIPs)
    print 'Destination IP addresses: ' + ', '.join(DstIPs)
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
                        type=str, action="store")

    args = parser.parse_args()

    if args.FileName:
        ParseLog(args.FileName)


if __name__ == "__main__":
    DoIt()
