package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/basht0p/chickadee/logger"
	"github.com/basht0p/chickadee/models"
)

func SendWebhookAlert(alertOptions models.AlertOptions, srcIp string) (err error) {

	data := models.WebhookData{
		SourceIP: srcIp,
	}

	body := models.Webhook{
		Type:      "scan.detected",
		Timestamp: time.Now().Local(),
		Data:      data,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		logger.Log(true, 1, 503, fmt.Sprintf("Could not parse webhook: %v", err))
		return fmt.Errorf("could not parse webhook: %v", err)
	}

	reader := bytes.NewReader(jsonBody)

	resp, err := http.Post(alertOptions.WebhookUrl, "application/json", reader)
	if err != nil {
		logger.Log(true, 1, 503, fmt.Sprintf("Could not post webhook: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Log(true, 1, 503, fmt.Sprintf("Webhook response error: %v", resp.Status))
	}

	return nil
}
