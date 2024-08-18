package main

import (
	"github.com/basht0p/chickadee/config"
	"github.com/basht0p/chickadee/detector"
	"github.com/basht0p/chickadee/models"

	"github.com/google/gopacket"
)

var configOptions models.Config = config.ReadConfig()

func main() {

	// Attempt to find the interface defined in the config
	iface, ifaceDesc := detector.FindIface(configOptions)

	// Open a pcap channel with that interface
	handle := detector.OpenPcap(iface, ifaceDesc, configOptions)

	// Init the detection functions against that new pcap channel
	detector.InitDetector(gopacket.NewPacketSource(handle, handle.LinkType()), configOptions)

	defer handle.Close()
}
