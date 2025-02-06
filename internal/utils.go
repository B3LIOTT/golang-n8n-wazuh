package internal

import (
	"fmt"
	"strings"
)

const (
	IDSAgentName           = "OPNsense.insoc.local"
	IDSGroup               = "suricata"
	SuricataAlertThreshold = 3
	WazuhAlertThreshold    = 7
)

var commonGroups = []string{"suricata", "sysmon", "syslog", "ossec"}

// Checks if the alert comes from Suricata
func IsSuricata(alert Alert) bool {
	for _, group := range alert.Rule.Groups {
		if group == IDSGroup {
			return alert.Agent.Name == IDSAgentName
		}
	}
	return false
}

// Gets mitre attack data from the Wazuh alert
func GetMitre(alert Alert) string {
	if len(alert.Rule.Mitre.Technique) > 0 {
		return fmt.Sprintf("mitre_techniques=%s,mitre_tactics=%s,mitre_id=%s",
			strings.Join(alert.Rule.Mitre.Technique, ";"),
			strings.Join(alert.Rule.Mitre.Tactic, ";"),
			strings.Join(alert.Rule.Mitre.ID, ";"))
	}
	return ""
}

// Gets the agent data from the Wazuh alert
func GetAgent(alert Alert) string {
	if IsSuricata(alert) {
		return fmt.Sprintf("src_ip=%s,src_port=%s,dest_ip=%s", alert.Data.SrcIP, alert.Data.SrcPort, alert.Data.DestIP)
	}

	if alert.Agent.IP == "" {
		alert.Agent.IP = "None"
	}
	return fmt.Sprintf("src_ip=%s,agent_id=%s", alert.Agent.IP, alert.Agent.ID)
}

// Build tags for our FormattedAlert
func GetTags(alert Alert) string {
	mitre := GetMitre(alert)
	if mitre != "" {
		return fmt.Sprintf("%s,%s", GetAgent(alert), mitre)
	}
	return GetAgent(alert)
}

// Returns a common type for our FormattedAlert
func GetType(alert Alert) string {
	for _, group := range commonGroups {
		for _, ruleGroup := range alert.Rule.Groups {
			if group == ruleGroup {
				return group
			}
		}
	}
	return alert.Rule.Groups[0]
}
