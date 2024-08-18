package config

import (
	"fmt"

	"github.com/basht0p/chickadee/models"
	"gopkg.in/ini.v1"
)

func ReadConfig() models.Config {

	var configModel models.Config

	iniContent, err := ini.Load("config.ini")
	if err != nil {
		fmt.Println("Error reading config:", err)
		return configModel
	}

	iniIface := iniContent.Section("").Key("interface").String()

	iniThresholdCount, err := iniContent.Section("").Key("threshold_count").Uint()
	if err != nil {
		fmt.Println("Error reading config:", err)
		return configModel
	}

	iniThresholdTime, err := iniContent.Section("").Key("threshold_time").Uint()
	if err != nil {
		fmt.Println("Error reading config:", err)
		return configModel
	}

	iniIgnoreTime, err := iniContent.Section("").Key("ignore_time").Uint()
	if err != nil {
		fmt.Println("Error reading config:", err)
		return configModel
	}

	configModel = models.Config{
		Iface:          iniIface,
		ThresholdCount: iniThresholdCount,
		ThresholdTime:  iniThresholdTime,
		IgnoreTime:     iniIgnoreTime,
	}

	return configModel
}
