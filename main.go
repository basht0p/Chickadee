package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/basht0p/chickadee/config"
	"github.com/basht0p/chickadee/detector"
	"github.com/basht0p/chickadee/logger"
	"github.com/google/gopacket"
	"github.com/kardianos/service"
)

type program struct{}

func (p *program) Start(s service.Service) error {
	err := logger.SetupEventLog("Chickadee")
	if err != nil {
		log.Fatalf("Failed to setup event log: %v", err)
	}

	go p.run()
	return nil
}

func (p *program) run() {
	defer func() {
		if r := recover(); r != nil {
			logger.Log(true, 2, 500, fmt.Sprintf("Service panicked: %v", r))
		}
	}()

	logger.Log(true, 0, 501, "Service started")

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		logger.Log(true, 2, 500, fmt.Sprintf("Failed to get absolute path: %v", err))
		log.Fatalf("Failed to get absolute path: %v", err)
	}
	err = os.Chdir(dir)
	if err != nil {
		logger.Log(true, 2, 500, fmt.Sprintf("Failed to change directory: %v", err))
		log.Fatalf("Failed to change directory: %v", err)
	}

	// Read Config
	detectionOptions, alertOptions := config.ReadConfig()

	// Attempt to find the interface defined in the config
	iface, ifaceDesc := detector.FindIface(detectionOptions.Iface)

	// Open a pcap channel with that interface
	handle := detector.OpenPcap(iface, ifaceDesc, detectionOptions)

	// Init the detection functions against that new pcap channel
	detector.InitDetector(gopacket.NewPacketSource(handle, handle.LinkType()), detectionOptions, alertOptions)

	defer handle.Close()

	select {}
}

func (p *program) Stop(s service.Service) error {
	logger.Log(true, 0, 502, "Service stopping")
	logger.CloseEventLog()
	return nil
}

func main() {
	svcConfig := &service.Config{
		Name:        "Chickadee",
		DisplayName: "Chickadee Network Scan Detection",
		Description: "A tiny Go-powered malicious network scan detector.",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		action := os.Args[1]
		if action == "install" || action == "uninstall" || action == "start" || action == "stop" || action == "restart" {
			err = service.Control(s, action)
			if err != nil {
				log.Fatalf("Failed to execute action %q: %v", action, err)
			}
		} else {
			log.Fatalf("Invalid action: %q. Valid actions are: %q", action, service.ControlAction)
		}
		return
	}

	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}
}
