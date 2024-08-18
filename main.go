package main

import (
	"github.com/basht0p/chickadee/config"
	"github.com/basht0p/chickadee/detector"

	"github.com/google/gopacket"
)

func main() {
	// Read Config
	detectionOptions, alertOptions := config.ReadConfig()

	// Attempt to find the interface defined in the config
	iface, ifaceDesc := detector.FindIface(detectionOptions.Iface)

	// Open a pcap channel with that interface
	handle := detector.OpenPcap(iface, ifaceDesc, detectionOptions)

	// Init the detection functions against that new pcap channel
	detector.InitDetector(gopacket.NewPacketSource(handle, handle.LinkType()), detectionOptions, alertOptions)

	defer handle.Close()
}
