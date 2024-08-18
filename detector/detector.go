package detector

import (
	"fmt"
	"log"
	"time"

	"github.com/basht0p/chickadee/models"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var scans = make(map[string][]models.PortScan)
var lastAlertTime = make(map[string]time.Time)

func FindIface(configOptions models.Config) (iface string, ifaceDesc string) {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		if len(device.Addresses) > 0 && device.Description == configOptions.Iface {
			iface = device.Name
			ifaceDesc = device.Description
			break
		}
	}

	if iface == "" {
		log.Fatal("No suitable device found")
	}

	fmt.Printf("Using device: %s (%s)\n", iface, ifaceDesc)

	return
}

func OpenPcap(iface string, ifaceDesc string, configOptions models.Config) *pcap.Handle {

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter("tcp[tcpflags] & tcp-syn != 0")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Listening for TCP packets...")
	return handle
}

func InitDetector(pktSrc *gopacket.PacketSource, configOptions models.Config) {
	for packet := range pktSrc.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN {
				srcIP := packet.NetworkLayer().NetworkFlow().Src().String()

				DetectPortScan(
					srcIP,
					uint16(tcp.DstPort),
					uint16(configOptions.ThresholdCount),
					uint16(configOptions.ThresholdTime),
					uint16(configOptions.IgnoreTime),
				)
			}
		}
	}
}

func DetectPortScan(ip string, port uint16, tCount uint16, tTime uint16, iTime uint16) {
	now := time.Now()

	if lastAlert, alerted := lastAlertTime[ip]; alerted && now.Sub(lastAlert) < time.Duration(iTime)*time.Second {
		return
	}

	if _, exists := scans[ip]; !exists {
		scans[ip] = []models.PortScan{}
	}

	var newScans []models.PortScan
	for _, scan := range scans[ip] {
		if now.Sub(scan.Timestamp) <= time.Duration(tTime)*time.Second {
			newScans = append(newScans, scan)
		}
	}
	scans[ip] = newScans

	scans[ip] = append(scans[ip], models.PortScan{Port: port, Timestamp: now})

	if len(scans[ip]) > int(tCount) {
		fmt.Printf("Potential port scan detected from IP: %s\n", ip)
		lastAlertTime[ip] = now
	}
}
