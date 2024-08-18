package logger

import (
	"fmt"
	"time"
)

func Log(winEvent bool, severity uint, message string) {

	var severityName string = "INFO"

	switch severity {
	case 0:
		severityName = "INFO"
	case 1:
		severityName = "WARN"
	case 2:
		severityName = "ERR"
	}

	fullMessage := time.Now().Local().Format("Mon Jan 02 2006 15:04:05.99") + " " + severityName + ": " + message

	if winEvent {
		fmt.Println("WIN: " + fullMessage)
	} else {
		fmt.Println(fullMessage)
	}

}
