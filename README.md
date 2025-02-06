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


# Details

This script sends Wazuh alerts to n8n in order to be automatically forwarded into TheHive4 (+ cool automatisation stuff). However it builds customized alerts tailored to TheHive alerts and custom fields I added.

Main structure:
| Champ       | Type   | Description               |
|------------|--------|---------------------------|
| Title      | string | Titre de l'alerte         |
| Description | string | Description détaillée    |
| Severity   | int    | Niveau de gravité         |
| Date       | string | Date de l'alerte          |
| Tags       | string | Mots-clés associés        |
| Type       | string | Type d'alerte             |
| Source     | string | Source de l'alerte        |

