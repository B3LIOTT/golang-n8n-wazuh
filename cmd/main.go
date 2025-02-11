package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/google/uuid"

	. "golang-n8n-wazuh/internal"
)

const (
	SuricataAlertThreshold = 3
	WazuhAlertThreshold    = 5
)

func checkErr(err error) {
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
}

func main() {
	alertFile := os.Args[1]
	// user := strings.Split(os.Args[2], ":")[0]
	hookURL := os.Args[3]

	// reads Wazuh alert file
	data, err := os.ReadFile(alertFile)
	checkErr(err)

	// unmarshals it
	var alert Alert
	err = json.Unmarshal(data, &alert)
	checkErr(err)

	// case disjunction between Suricata and Wazuh
	var severity int
	var source string

	if IsSuricata(alert) {

		suriSev, err := strconv.Atoi(alert.Data.Alert.Severity)
		checkErr(err)

		if suriSev >= SuricataAlertThreshold {
			if suriSev > 5 {
				severity = 3
			} else if suriSev > 3 {
				severity = 2
			} else {
				severity = 1
			}
			source = "Suricata IDS"
		} else {
			os.Exit(0)
		}
	} else if alert.Rule.Level >= WazuhAlertThreshold {
		if alert.Rule.Level > 10 {
			severity = 3
		} else if alert.Rule.Level > 5 {
			severity = 2
		} else {
			severity = 1
		}
		source = alert.Agent.Name
	} else {
		os.Exit(0)
	}

	customFields := GetCustomFields(alert)
	formattedAlert := FormattedAlert{
		Title:        alert.Rule.Description,
		Description:  "Alert from: " + alert.Agent.Name,
		Severity:     severity,
		Date:         alert.Timestamp,
		Tags:         GetTags(alert),
		Type:         GetType(alert),
		Source:       source,
		SourceRef:    uuid.New().String(),
		CustomFields: customFields,
	}

	payload, err := json.Marshal(formattedAlert)
	checkErr(err)

	resp, err := http.Post(hookURL, "application/json", bytes.NewBuffer(payload))
	checkErr(err)

	defer resp.Body.Close()
}
