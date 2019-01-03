#!/usr/bin/env bash
CUR_PATH=`pwd`
cp analyze $1
cd $1
./analyze h1.pcap h2.pcap h3.pcap h4.pcap h5.pcap h6.pcap h7.pcap h8.pcap
cd $CUR_PATH