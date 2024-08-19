package detector

import (
	"fmt"
	"log"
	"time"

	"github.com/basht0p/chickadee/alerts"
	"github.com/basht0p/chickadee/logger"
	"github.com/basht0p/chickadee/models"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var scans = make(map[string][]models.PortScan)
var lastAlertTime = make(map[string]time.Time)

func FindIface(ifaceQuery string) (iface string, ifaceDesc string) {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		if device.Description == ifaceQuery {
			if len(device.Addresses) > 0 {
				iface = device.Name
				ifaceDesc = device.Description
				break
			} else {
				log.Fatal(fmt.Errorf("device (%v) was found, but no usable addresses were configured. exiting", ifaceDesc))
			}
		}
	}

	if iface == "" {
		log.Fatal(fmt.Errorf("device (%v) was not found. exiting", ifaceQuery))
	}

	logger.Log(false, 0, ("Interface found! Using: " + ifaceDesc + " (" + iface + ")"))

	return
}

func OpenPcap(iface string, ifaceDesc string, detectionOptions models.DetectionOptions) *pcap.Handle {

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter("tcp[tcpflags] & tcp-syn != 0")
	if err != nil {
		log.Fatal(err)
	}

	logger.Log(false, 0, ("Packet capture initialized. Listening for scans..."))
	return handle
}

func InitDetector(pktSrc *gopacket.PacketSource, detectionOptions models.DetectionOptions, alertOptions models.AlertOptions) {
	for packet := range pktSrc.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN {
				srcIP := packet.NetworkLayer().NetworkFlow().Src().String()

				DetectPortScan(
					srcIP,
					uint16(tcp.DstPort),
					uint16(detectionOptions.ThresholdCount),
					uint16(detectionOptions.ThresholdTime),
					uint16(detectionOptions.IgnoreTime),
					alertOptions,
				)
			}
		}
	}
}

func DetectPortScan(ip string, port uint16, tCount uint16, tTime uint16, iTime uint16, alertOptions models.AlertOptions) {
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
		logger.Log(false, 1, ("Port scan detected from: " + ip))
		alerts.TriggerAlert(alertOptions, ("Port scan detected from: " + ip), ip)
		lastAlertTime[ip] = now
	}
}
