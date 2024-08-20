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

func FindIface(detectionOptions *models.DetectionOptions) (iface string, ifaceDesc string) {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		logger.Log(true, 2, 500, fmt.Sprintf("Fatal error using pcap.FindAllDevs(): %v", err))
		log.Fatal(err)
	}

	for _, device := range devices {
		if device.Description == detectionOptions.Iface {
			if len(device.Addresses) > 0 {
				iface = device.Name
				ifaceDesc = device.Description

				for _, address := range device.Addresses {
					detectionOptions.ExcludedIps = append(detectionOptions.ExcludedIps, address.IP.String())
				}

				break
			} else {
				logger.Log(true, 2, 500, fmt.Sprintf("Device (%v) was found, but no usable addresses were configured. Exiting...", detectionOptions.Iface))
				log.Fatal(fmt.Errorf("device (%v) was found, but no usable addresses were configured. exiting", ifaceDesc))
			}
		}
	}

	if iface == "" {
		logger.Log(true, 2, 500, fmt.Sprintf("Device (%v) was not found. Using first interface found with valid address...", detectionOptions.Iface))
		for _, device := range devices {
			if len(device.Addresses) > 0 {
				iface = device.Name
				ifaceDesc = device.Description

				for _, address := range device.Addresses {
					detectionOptions.ExcludedIps = append(detectionOptions.ExcludedIps, address.IP.String())
				}

				break
			}
		}
	}

	logger.Log(true, 0, 510, ("Interface found! Using: " + ifaceDesc + " (" + iface + ")"))

	return
}

func OpenPcap(iface string, ifaceDesc string, detectionOptions *models.DetectionOptions) *pcap.Handle {

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		logger.Log(true, 2, 500, fmt.Sprintf("Fatal error opening pcap on interface %v: %v", iface, err))
		log.Fatal(err)
	}

	err = handle.SetBPFFilter("tcp[tcpflags] & tcp-syn != 0")
	if err != nil {
		logger.Log(true, 2, 500, fmt.Sprintf("Fatal error setting BPF Filter: %v", err))
		log.Fatal(err)
	}

	logger.Log(true, 0, 511, ("Packet capture initialized. Listening for scans..."))
	return handle
}

func InitDetector(pktSrc *gopacket.PacketSource, detectionOptions *models.DetectionOptions, alertOptions *models.AlertOptions) {
	for packet := range pktSrc.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp.SYN {
				srcIP := packet.NetworkLayer().NetworkFlow().Src().String()

				DetectPortScan(
					srcIP,
					uint16(tcp.DstPort),
					detectionOptions,
					alertOptions,
				)
			}
		}
	}
}

func IsIpExcluded(srcIp string, detectionOptions *models.DetectionOptions) bool {
	for _, ip := range detectionOptions.ExcludedIps {
		if ip == srcIp {
			return true
		}
	}
	return false
}

func DetectPortScan(ip string, port uint16, detectionOptions *models.DetectionOptions, alertOptions *models.AlertOptions) {
	now := time.Now()

	if lastAlert, alerted := lastAlertTime[ip]; alerted && now.Sub(lastAlert) < time.Duration(detectionOptions.IgnoreTime)*time.Second {
		return
	}

	if _, exists := scans[ip]; !exists {
		scans[ip] = []models.PortScan{}
	}

	var newScans []models.PortScan
	for _, scan := range scans[ip] {
		if now.Sub(scan.Timestamp) <= time.Duration(detectionOptions.ThresholdTime)*time.Second {
			newScans = append(newScans, scan)
		}
	}
	scans[ip] = newScans

	scans[ip] = append(scans[ip], models.PortScan{Port: port, Timestamp: now})

	if len(scans[ip]) > int(detectionOptions.ThresholdCount) {
		if !IsIpExcluded(ip, detectionOptions) {
			logger.Log(true, 1, 515, ("Port scan detected from: " + ip))
			alerts.TriggerAlert(alertOptions, ("Port scan detected from: " + ip), ip)
			lastAlertTime[ip] = now
		}
	}
}
