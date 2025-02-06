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
		SrcIP   string `json:"src_ip"`
		SrcPort string `json:"src_port"`
		DestIP  string `json:"dest_ip"`
		Alert   struct {
			Severity int `json:"severity"`
		} `json:"alert"`
	} `json:"data"`
	Timestamp string `json:"timestamp"`
}

// Formated alert structure
// It defines the alert structure
// to be sent to n8n
type FormattedAlert struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    int    `json:"severity"`
	Date        string `json:"date"`
	Tags        string `json:"tags"`
	Type        string `json:"type"`
	Source      string `json:"source"`
}
