package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenOffline("capture/http.pcap")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet) // Do something with a packet here.
	}
}

func handlePacket(packet gopacket.Packet) {

	// Get the TCP layer from this packet
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if tcpLayer != nil {

		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From: src port %6d\tTo: dst port %6d\t", tcp.SrcPort, tcp.DstPort)
		fmt.Printf("Ack: %12v\t", tcp.Ack)
	}

	// Iterate over all layers, printing out each layer type
	for _, layer := range packet.Layers() {
		layerType := layer.LayerType()
		fmt.Printf("%8v %5v", layerType, len(layer.LayerPayload()))
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())
	}
	fmt.Println("")

}
