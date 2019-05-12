// Copyright (c) 2019, Adel "0x4d31" Karimi.
// All rights reserved.
//
// Licensed under the BSD 3-Clause license.
// For full license text, see the LICENSE file in the repo root
// or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/0x4d31/quick"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	//device string = "en0"
	snaplen int32 = 1600
	promisc bool = false
	handle *pcap.Handle
	filter string = "udp and dst port 443"
)

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil && ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		udp, _ := udpLayer.(*layers.UDP)
		var clientHello = quick.CHLO{}
		err := clientHello.DecodeCHLO(udp.LayerPayload())
		switch err {
		case nil:
		case quick.ErrWrongType:
			return
		default:
			log.Println("Error:", err)
			return
		}
		log.Printf("%s:%s -> %s:%s [QUIC]  SNI: %s\n", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort, clientHello.TagValues["SNI"])
		fmt.Println(clientHello)
	}
	return
}

func main() {
	iface := flag.String("i", "en0", "Specify a network interface to capture on")
	flag.Parse()

	// Open device
	handle, err := pcap.OpenLive(*iface, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Set filter
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Listening on", *iface, "\n")
	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}
