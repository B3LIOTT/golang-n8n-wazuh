# About

This repo contains a n8n integration for Wazuh, in golang. It takes some alert fileds I needed in my SOC project to be forwarded to n8n. You can easily customize what json parameters you want to be sent to n8n by modifying the `Alert` model. 

# Compile

Target OS is Linux:
```bash
GOOS=linux GOARCH=amd64 go build -o custom-n8n
```

# Usage

## Tests
If you want to test it you can use alert samples [here](./alerts-examples/).

Here is an example for the suricata alert:
```bash
./custom-n8n ../alerts-examples/suricata.json useless "http://192.168.7.15:5678/webhook-test/7ceae612-e110-4adf-8191-95557ec9b251"
```

## Within Wazuh
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

## Main structure

The main alert structure is as it follows:
| Field        | Type   |
|--------------|--------|
| Title        | string | 
| Description  | string | 
| Severity     | int    | 
| Date         | string |
| Tags         | string |
| Type         | string | 
| Source       | string |
| CustomFields | dict   |

## Tags

Tags are very useful to add generic infos to an alert. Here are the tags I defined:
| Tag              | Example                                  |
|------------------|------------------------------------------|
| manager type     | wazuh, suricata, opnsense                | 
| mitre techniques | bruteforce, privilege escalation         | 
| groups           | ossec, sysmon, vulnerability-detector    | 


# Custom fileds

Custom fields are useful to add more details to the alert.

## Wazuh agent

| Custom field | Example        |
|--------------|----------------|
| agent name   | DESKTOP-XXXXXX |   
| agent id     | 001            | 
| agent ip     | X.X.X.X        | 

## Suricata

| Custom field | Example        |
|--------------|----------------|
| src ip       | X.X.X.X        | 
| src port     | 1234           | 
| dest ip      | X.X.X.X        | 
| dest port    | 5678           | 
| protocol     | TCP            | 
| url          | .../login.php  | 

## OPNsense

| Custom field | Example        |
|--------------|----------------|
| src ip       | X.X.X.X        | 
| src port     | 1234           | 
| dest ip      | X.X.X.X        | 
| dest port    | 5678           | 
| protocol     | TCP            | 

## Sysmon

TODO ...