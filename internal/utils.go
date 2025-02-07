package internal

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

const (
	FirewallAgentName = "OPNsense.insoc.local"
	IDSGroup          = "suricata"
)

var commonGroups = []string{"suricata", "sysmon", "syslog", "ossec"}

// Checks if the alert comes from Suricata
func IsSuricata(alert Alert) bool {
	for _, group := range alert.Rule.Groups {
		if group == IDSGroup {
			return true
		}
	}
	return false
}

// Checks if the alert comes from the firewall
func IsFirewall(alert Alert) bool {
	return alert.Agent.Name == FirewallAgentName
}

// Gets mitre attack data from the Wazuh alert
func JoinMitreTechs(alert Alert) string {
	if len(alert.Rule.Mitre.Technique) > 0 {
		return strings.Join(alert.Rule.Mitre.Technique, ",")
	}
	return ""
}

// Gets the groups from the Wazuh alert
func JoinGroups(alert Alert) string {
	return strings.Join(alert.Rule.Groups, ",")
}

// Build tags for our FormattedAlert
func GetTags(alert Alert) string {
	return fmt.Sprintf("%s,%s,%s", alert.Manager.Name, JoinGroups(alert), JoinMitreTechs(alert))
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

// Builds a CustomFields object for our FormattedAlert
func GetCustomFields(alert Alert) CustomFields {
	var cf CustomFields

	if IsFirewall(alert) {
		cf = CustomFields{
			SrcIp:    alert.Data.SrcIp,
			SrcPort:  alert.Data.SrcPort,
			DestIP:   alert.Data.DestIp,
			DestPort: alert.Data.DestPort,
			Protocol: alert.Data.Protocol,
		}
		if IsSuricata(alert) {
			cf.Url = alert.Data.HttpSuricata.Url
		}
	} else {
		cf = CustomFields{
			AgentName: alert.Agent.Name,
			AgentId:   alert.Agent.ID,
			AgentIp:   alert.Agent.IP,
		}
	}
	cf.Hash = cf.GetHash()
	return cf
}

// CustomFields Object to string
func (c CustomFields) ToString() string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%s",
		c.AgentName, c.AgentId, c.AgentIp, c.SrcIp, c.SrcPort,
		c.DestIP, c.DestPort, c.Protocol, c.Url)
}

// Gets a blake hash of CustomFields
func (c CustomFields) GetHash() string {
	data := []byte(c.ToString())
	hash := blake2b.Sum256(data)
	return fmt.Sprintf("%x", hash)
}
