package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/ini.v1"
)

type PortScan struct {
	Port      uint16
	Timestamp time.Time
}

type Config struct {
	Interface string
}

var scans = make(map[string][]PortScan)
var lastAlertTime = make(map[string]time.Time) // Track the last alert time for each IP

func readConfig() (*ini.File, error) {

	cfg, err := ini.Load("config.ini")
	if err != nil {
		fmt.Println("Error reading config:", err)
		return nil, err
	}

	return cfg, nil
}

func main() {
	// Find all network interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	config, err := readConfig()

	if err != nil {
		log.Fatal(err)
	}

	// Choose the first device that matches your criteria
	var iface string
	var ifaceDesc string
	for _, device := range devices {
		if len(device.Addresses) > 0 && device.Description == config.Section("").Key("interface").String() {
			iface = device.Name
			ifaceDesc = device.Description
			break
		}
	}

	if iface == "" {
		log.Fatal("No suitable device found")
	}

	fmt.Printf("Using device: %s (%s)\n", iface, ifaceDesc)

	iface = "\\Device\\NPF_{38514249-51D8-46B6-961C-088A6E47AD0E}"
	// Open the device for capturing
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set the BPF filter for capturing only TCP packets with SYN flag
	err = handle.SetBPFFilter("tcp[tcpflags] & tcp-syn != 0")
	if err != nil {
		log.Fatal(err)
	}

	// Use a packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Listening for TCP SYN packets...")
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN {
				srcIP := packet.NetworkLayer().NetworkFlow().Src().String()
				detectPortScan(srcIP, uint16(tcp.DstPort))
			}
		}
	}
}

func detectPortScan(ip string, port uint16) {
	// Current time
	now := time.Now()

	if lastAlert, alerted := lastAlertTime[ip]; alerted && now.Sub(lastAlert) < 30*time.Second {
		return
	}

	// If the IP doesn't exist in the map, initialize its slice
	if _, exists := scans[ip]; !exists {
		scans[ip] = []PortScan{}
	}

	// Filter out old scans (older than 5 seconds)
	var newScans []PortScan
	for _, scan := range scans[ip] {
		if now.Sub(scan.Timestamp) <= 5*time.Second {
			newScans = append(newScans, scan)
		}
	}
	scans[ip] = newScans

	// Add the new port scan
	scans[ip] = append(scans[ip], PortScan{Port: port, Timestamp: now})

	// Check if more than 10 ports have been scanned within 5 seconds
	if len(scans[ip]) > 10 {
		fmt.Printf("Potential port scan detected from IP: %s\n", ip)
		lastAlertTime[ip] = now
	}
}
