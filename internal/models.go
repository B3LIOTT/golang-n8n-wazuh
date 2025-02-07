package internal

// Wazuh alert structure
// It gets every field I wanted
// to be forwarded to n8n
type Alert struct {
	Agent struct {
		Name string `json:"name"`
		IP   string `json:"ip,omitempty"`
		ID   string `json:"id"`
	} `json:"agent"`

	Manager struct {
		Name string `json:"name"`
	} `json:"manager"`

	Rule struct {
		Description string   `json:"description"`
		Level       int      `json:"level"`
		Groups      []string `json:"groups"`
		Mitre       struct {
			Technique []string `json:"technique"`
			Tactic    []string `json:"tactic"`
			ID        []string `json:"id"`
		} `json:"mitre,omitempty"`
	} `json:"rule"`

	Data struct {
		SrcIp        string `json:"src_ip,srcip"`
		SrcPort      string `json:"src_port,srcport"`
		DestIp       string `json:"dest_ip,dstip"`
		DestPort     string `json:"dest_port,dstport"`
		Protocol     string `json:"proto,protocol"`
		HttpSuricata struct {
			Url string `json:"url"`
		} `json:"http,omitempty"`
		Alert struct {
			Severity string `json:"severity"`
		} `json:"alert,omitempty"`
	} `json:"data,omitempty"`

	Timestamp string `json:"timestamp"`
}

// Formated alert structure
// It defines the alert structure
// to be sent to n8n
type FormattedAlert struct {
	Title        string       `json:"title"`
	Description  string       `json:"description"`
	Severity     int          `json:"severity"`
	Date         string       `json:"date"`
	Tags         string       `json:"tags"`
	Type         string       `json:"type"`
	Source       string       `json:"source"`
	SourceRef    string       `json:"sourceRef"`
	CustomFields CustomFields `json:"customFields"`
}

// CustomFields defined in TheHive alerts
type CustomFields struct {
	Hash      string `json:"hash"`
	AgentName string `json:"agent_name,omitempty"`
	AgentId   string `json:"agent_id,omitempty"`
	AgentIp   string `json:"agent_ip,omitempty"`
	SrcIp     string `json:"src_ip,omitempty"`
	SrcPort   string `json:"src_port,omitempty"`
	DestIP    string `json:"dest_ip,omitempty"`
	DestPort  string `json:"dest_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Url       string `json:"url,omitempty"`
}
