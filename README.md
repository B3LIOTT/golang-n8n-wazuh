# About

This repo contains a n8n integration for Wazuh, in golang. It takes some alert fileds I needed in my SOC project to be forwarded to n8n. You can easily customize what json parameters you want to be sent to n8n by modifying the `Alert` model. 

# Compile

Target OS is Linux:
```bash
GOOS=linux GOARCH=amd64 go build -o custom-n8n
```

# Usage

This script has to be in `/var/ossec/integrations/` in your Wazuh Manager, as `custom-n8n`. You also have to update `/var/ossec/etc/ossec.conf` in order to define a new integration:
```xml
<integration>
  <name>custom-n8n</name>
  <level>3</level>
  <hook_url>http://<IP SERVEUR>:5678/api/hook...</hook_url>
  <alert_format>json</alert_format>
</integration>
```