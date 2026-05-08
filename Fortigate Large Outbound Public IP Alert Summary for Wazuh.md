# Fortigate Large Outbound Public IP Alert Summary for Wazuh

## Table of Contents

- [Tested Version](#tested-version)
- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Integration Steps](#integration-steps)
  - [Step 1: Install required packages](#step-1-install-required-packages)
  - [Step 2: Add the Fortigate large outbound traffic rule](#step-2-add-the-fortigate-large-outbound-traffic-rule)
  - [Step 3: Add the Wazuh summary alert rule](#step-3-add-the-wazuh-summary-alert-rule)
  - [Step 4: Create the OpenSearch notification channel](#step-4-create-the-opensearch-notification-channel)
  - [Step 5: Create the OpenSearch Alerting monitor](#step-5-create-the-opensearch-alerting-monitor)
  - [Step 6: Add the webhook listener script](#step-6-add-the-webhook-listener-script)
  - [Step 7: Configure the script as a systemd service](#step-7-configure-the-script-as-a-systemd-service)
  - [Step 8: Validate the integration](#step-8-validate-the-integration)
- [Sample Fortigate log](#sample-fortigate-log)
- [Expected summary event sent to Wazuh socket](#expected-summary-event-sent-to-wazuh-socket)
- [Security notes](#security-notes)
- [Conclusion](#conclusion)
- [References](#references)

## Tested Version

| Wazuh version | Component | Deployment type | OS |
|---|---|---|---|
| 4.x | Wazuh manager, Wazuh indexer, Wazuh dashboard | Single-node or manager-accessible deployment | Linux |

> Update this table with the exact Wazuh version and OS used in your environment before publishing.

## Overview

This integration detects Fortigate traffic events where the outbound transferred bytes are greater than or equal to `1000000000` and the destination IP is public. The detection flow uses a Wazuh rule to identify large outbound Fortigate traffic, an OpenSearch Alerting monitor to query indexed alerts five minute, and a Python Flask webhook service to summarize the matching alerts.

When the monitor condition is met, OpenSearch Alerting sends the matching alerts to the local webhook. The webhook builds one compact JSON summary event and pushes it to the Wazuh manager analysis socket. Wazuh then decodes the event using the JSON decoder and triggers a custom Wazuh alert for the summary event.

This avoids creating one separate follow-up alert per indexed hit. Instead, all matching alerts in the monitor window are grouped into a single summary alert.

## Architecture

```text
Fortigate log
   |
   v
Wazuh manager receives and decodes Fortigate traffic event
   |
   v
Custom Wazuh rule 101145 detects large outbound traffic
   |
   v
Alert is indexed into wazuh-alerts-4.x-*
   |
   v
OpenSearch Alerting monitor runs every 5 minute
   |
   v
Monitor searches the last 5 minutes for rule.id 101145 and excludes private destination IP ranges
   |
   v
Webhook notification channel posts matching alerts to Flask service
   |
   v
Flask service creates one compact JSON summary event
   |
   v
Summary event is written to /var/ossec/logs/fortigate_webhook_enriched.log
   |
   v
Summary event is pushed to /var/ossec/queue/sockets/queue
   |
   v
Wazuh JSON decoder parses the event
   |
   v
Custom Wazuh rule 101146 generates the final dashboard alert
```

## Requirements

- Wazuh manager access.
- Wazuh dashboard or Wazuh indexer admin credentials.
- Python 3 and `pip3` installed on the host running the webhook service.
- Network reachability from the Wazuh indexer or dashboard notification service to the webhook URL.
- Fortigate logs already ingested and decoded by Wazuh.

## Integration Steps

### Step 1: Install required packages

For RHEL, CentOS, Rocky Linux, or Amazon Linux:

```bash
yum install -y jq python3 python3-pip
pip3 install flask
```

For Ubuntu or Debian:

```bash
apt update
apt install -y jq python3 python3-pip
pip3 install flask
```

Verify the installation:

```bash
python3 --version
pip3 --version
```

### Step 2: Add the Fortigate large outbound traffic rule

Add the following rule to your local Wazuh rules file, for example:

```bash
vi /var/ossec/etc/rules/local_rules.xml
```

Add this rule block:

```xml
<group name="fortigate,traffic,large_outbound,">

  <rule id="101145" level="12">
    <if_sid>81618</if_sid>
    <field name="type">^traffic$</field>
    <field name="sentbyte" type="pcre2">^[1-9][0-9]{9,}$</field>
    <description>Fortigate: Large outbound traffic detected.</description>
  </rule>

</group>
```

Restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
systemctl status wazuh-manager --no-pager
```

### Step 3: Add the Wazuh summary alert rule

Add the following rule to the same local rules file:

```xml
<group name="opensearch_alerting,fortigate,enrichment,">

  <rule id="101146" level="10">
    <if_sid>86600</if_sid>
    <field name="integration">^opensearch_alerting_webhook$</field>
    <field name="event_type">^fortigate_large_outbound_summary$</field>
    <description>Wazuh Alerting: Fortigate large outbound traffic to public IP alerts summary</description>
  </rule>

</group>
```

Restart the Wazuh manager again:

```bash
systemctl restart wazuh-manager
```

> Rule `101146` depends on the JSON event being injected into the Wazuh manager socket by the Flask script.

### Step 4: Create the OpenSearch notification channel

Create a webhook notification channel. Run this on the Wazuh indexer or a host that can reach the Wazuh indexer API:

```bash
curl -sk -u admin:<password> -H 'Content-Type: application/json' \
  -X POST 'https://localhost:9200/_plugins/_notifications/configs' \
  -d '{
    "name": "fortigate-enrichment-webhook",
    "config": {
      "name": "fortigate-enrichment-webhook",
      "description": "POST Fortigate large outbound alerts to local Python webhook",
      "config_type": "webhook",
      "is_enabled": true,
      "webhook": {
        "url": "http://<manager-IP>:5000/enrich"
      }
    }
  }' | jq -r '.config_id'
```

Replace:

- `<password>` with the Wazuh indexer admin password.
- `<manager-IP>` with the IP address of the Wazuh manager or the server running the Flask webhook.

Copy the returned `config_id`. Use it as the `destination_id` in the monitor configuration.

### Step 5: Create the OpenSearch Alerting monitor

Replace `<password>` with your Wazuh indexer admin password and `<DEST_ID>` with the notification channel `config_id` from the previous step.

```bash
curl -sk -u admin:<password> -H 'Content-Type: application/json' \
  -X POST 'https://localhost:9200/_plugins/_alerting/monitors' \
  -d '{
    "name": "Fortigate large outbound public IP webhook",
    "enabled": true,
    "monitor_type": "query_level_monitor",
    "schedule": {
      "period": {
        "interval": 5,
        "unit": "MINUTES"
      }
    },
    "inputs": [
      {
        "search": {
          "indices": ["wazuh-alerts-4.x-*"],
          "query": {
            "size": 100,
            "_source": [
              "timestamp",
              "data.srcip",
              "data.srcport",
              "data.dstip",
              "data.dstport",
              "data.app",
              "data.appcat",
              "data.sentbyte",
              "data.type",
              "rule.id"
            ],
            "query": {
              "bool": {
                "filter": [
                  { "term": { "rule.id": "101145" } },
                  { "range": { "@timestamp": { "gte": "now-5m", "lte": "now" } } }
                ],
                "must_not": [
                  { "range": { "data.dstip": { "gte": "10.0.0.0", "lte": "10.255.255.255" } } },
                  { "range": { "data.dstip": { "gte": "172.16.0.0", "lte": "172.31.255.255" } } },
                  { "range": { "data.dstip": { "gte": "192.168.0.0", "lte": "192.168.255.255" } } },
                  { "range": { "data.dstip": { "gte": "127.0.0.0", "lte": "127.255.255.255" } } },
                  { "range": { "data.dstip": { "gte": "169.254.0.0", "lte": "169.254.255.255" } } },
                  { "range": { "data.dstip": { "gte": "224.0.0.0", "lte": "239.255.255.255" } } },
                  { "term": { "data.integration": "opensearch_alerting_webhook" } },
                  { "term": { "data.event_type": "fortigate_large_outbound_summary" } }
                ]
              }
            },
            "sort": [
              { "@timestamp": { "order": "desc" } }
            ]
          }
        }
      }
    ],
    "triggers": [
      {
        "name": "Send Fortigate large outbound public IP alerts to webhook",
        "severity": "1",
        "condition": {
          "script": {
            "source": "return ctx.results[0].hits.total.value > 0"
          }
        },
        "actions": [
          {
            "name": "POST Fortigate public IP alert details to Python webhook",
            "destination_id": "<DEST_ID>",
            "message_template": {
              "source": "{\"monitor_name\":\"{{ctx.monitor.name}}\",\"trigger_name\":\"{{ctx.trigger.name}}\",\"period_start\":\"{{ctx.periodStart}}\",\"period_end\":\"{{ctx.periodEnd}}\",\"total_hits\":{{ctx.results.0.hits.total.value}},\"hits\":{{#toJson}}ctx.results.0.hits.hits{{/toJson}}}"
            },
            "throttle_enabled": false
          }
        ]
      }
    ]
  }'
```

> Important: This monitor excludes common private, loopback, link-local, and multicast destination ranges. This is a practical filter, not a perfect replacement for proper IP classification. OpenSearch range queries on IP fields only work correctly if `data.dstip` is mapped as an IP field. If `data.dstip` is mapped as a keyword, validate carefully before relying on this in production.

### Step 6: Add the webhook listener script

Create the script:

```bash
cat > /var/ossec/integrations/fortigate_webhook_enricher.py << 'PYEOF'
#!/usr/bin/env python3

from flask import Flask, request, jsonify
from datetime import datetime, timezone
import json
import os
import socket
import traceback

app = Flask(__name__)

LOG_FILE = "/var/ossec/logs/fortigate_webhook_enriched.log"
DEBUG_FILE = "/var/ossec/logs/fortigate_webhook_enriched_debug.log"
WAZUH_SOCKET = "/var/ossec/queue/sockets/queue"

# This appears as the event location in Wazuh.
WAZUH_LOCATION = "fortigate_webhook_enricher"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_file_log(event):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")


def write_debug(message):
    os.makedirs(os.path.dirname(DEBUG_FILE), exist_ok=True)

    with open(DEBUG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{utc_now()} {message}\n")


def send_to_wazuh(event):
    """
    Push JSON event directly to the Wazuh manager analysis socket.

    Format:
    1:<location>:<json_event>
    """

    message = f"1:{WAZUH_LOCATION}:{json.dumps(event, separators=(',', ':'), ensure_ascii=False)}"

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(WAZUH_SOCKET)
        sock.send(message.encode("utf-8"))
    finally:
        sock.close()


def build_summary_event(hits):
    """
    Build one compact JSON event with only the required fields.
    """

    alerts = []

    for hit in hits:
        source = hit.get("_source", {})
        data = source.get("data", {})
        rule = source.get("rule", {})

        alert = {
            "timestamp": source.get("timestamp") or source.get("@timestamp"),
            "data": {
                "srcip": data.get("srcip"),
                "srcport": data.get("srcport"),
                "dstip": data.get("dstip"),
                "dstport": data.get("dstport"),
                "fortigate": {
                    "app": data.get("app"),
                    "appcat": data.get("appcat"),
                    "sentbyte": data.get("sentbyte"),
                    "type": data.get("type")
                }
            },
            "rule": {
                "id": rule.get("id")
            }
        }

        alerts.append(alert)

    return {
        "timestamp": utc_now(),
        "integration": "opensearch_alerting_webhook",
        "event_type": "fortigate_large_outbound_summary",
        "total_alerts": len(alerts),
        "alerts": alerts
    }


@app.route("/enrich", methods=["POST"])
def enrich():
    try:
        payload = request.get_json(force=True, silent=False)

        hits = payload.get("hits", [])

        if not isinstance(hits, list):
            return jsonify({
                "status": "error",
                "message": "Invalid payload. Expected hits as list."
            }), 400

        if len(hits) == 0:
            return jsonify({
                "status": "ignored",
                "message": "No hits received."
            }), 200

        summary_event = build_summary_event(hits)

        # Write compact JSON event to file.
        write_file_log(summary_event)

        # Push the same compact JSON event to the Wazuh socket.
        send_to_wazuh(summary_event)

        return jsonify({
            "status": "success",
            "message": "Compact event written to file and pushed to Wazuh socket.",
            "total_alerts": summary_event["total_alerts"]
        }), 200

    except Exception as e:
        error_event = {
            "timestamp": utc_now(),
            "integration": "opensearch_alerting_webhook",
            "event_type": "fortigate_webhook_error",
            "error": str(e)
        }

        write_file_log(error_event)
        write_debug(traceback.format_exc())

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
PYEOF
```

Set ownership and permissions:

```bash
chmod 750 /var/ossec/integrations/fortigate_webhook_enricher.py
chown root:wazuh /var/ossec/integrations/fortigate_webhook_enricher.py
```

### Step 7: Configure the script as a systemd service

Create the service file:

```bash
cat > /etc/systemd/system/fortigate-webhook-enricher.service << 'EOF'
[Unit]
Description=Fortigate OpenSearch Alerting Webhook Enricher for Wazuh
After=network.target wazuh-manager.service
Wants=wazuh-manager.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /var/ossec/integrations/fortigate_webhook_enricher.py
Restart=always
RestartSec=5
User=root
Group=wazuh

# Basic hardening. Keep this practical because the service must write under /var/ossec/logs
# and access /var/ossec/queue/sockets/queue.
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start the service:

```bash
systemctl daemon-reload
systemctl enable fortigate-webhook-enricher
systemctl start fortigate-webhook-enricher
```

Check the service status:

```bash
systemctl status fortigate-webhook-enricher --no-pager
journalctl -u fortigate-webhook-enricher -f
```

Test the health endpoint:

```bash
curl -s http://127.0.0.1:5000/health | jq
```

Expected output:

```json
{
  "status": "ok"
}
```

### Step 8: Validate the integration

Check whether the webhook file log is being written:

```bash
tail -f /var/ossec/logs/fortigate_webhook_enriched.log
```

Check debug errors:

```bash
tail -f /var/ossec/logs/fortigate_webhook_enriched_debug.log
```

Check Wazuh alerts:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | grep 'fortigate_large_outbound_summary'
```

Search from Wazuh dashboard Dev Tools:

```json
GET wazuh-alerts-4.x-*/_search
{
  "size": 10,
  "query": {
    "bool": {
      "filter": [
        { "term": { "rule.id": "101146" } },
        { "term": { "data.integration": "opensearch_alerting_webhook" } },
        { "term": { "data.event_type": "fortigate_large_outbound_summary" } }
      ]
    }
  },
  "sort": [
    { "@timestamp": { "order": "desc" } }
  ]
}
```

## Sample Fortigate log

Use a sample log similar to the following to reproduce the detection:

```text
date=2026-05-08 time=10:30:45 devname="FGT60F" devid="FGT123456789" eventtime=1778216445 tz="+0530" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.25 srcport=54321 srcintf="lan" srcintfrole="lan" dstip=8.8.8.8 dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=123456789 proto=6 action="accept" policyid=1 policytype="policy" service="HTTPS" trandisp="snat" transip=203.0.113.10 transport=54321 appid=40568 app="HTTPS.BROWSER" appcat="Web.Client" apprisk="medium" sentbyte=1500000000 rcvdbyte=500000 sentpkt=100000 rcvdpkt=500 duration=3600
```

The `sentbyte=1500000000` value should match rule `101145` because it is greater than `1000000000`.

## Expected summary event sent to Wazuh socket

The Flask script sends a compact event similar to this to the Wazuh manager socket:

```json
{
  "timestamp": "2026-05-08T05:00:00.000000+00:00",
  "integration": "opensearch_alerting_webhook",
  "event_type": "fortigate_large_outbound_summary",
  "total_alerts": 1,
  "alerts": [
    {
      "timestamp": "2026-05-08T10:30:45+05:30",
      "data": {
        "srcip": "192.168.1.25",
        "srcport": "54321",
        "dstip": "8.8.8.8",
        "dstport": "443",
        "fortigate": {
          "app": "HTTPS.BROWSER",
          "appcat": "Web.Client",
          "sentbyte": "1500000000",
          "type": "traffic"
        }
      },
      "rule": {
        "id": "101145"
      }
    }
  ]
}
```

The actual socket message format is:

```text
1:fortigate_webhook_enricher:<json_event>
```

## Duplicate summary alerts

The monitor runs 5 minute and searches a five-minute window. That means if you need to search for a long time range update it on the alerting module and also change the run time equal to that to avoid duplicate alerts. Alos, avoid searching for large time range if you have high number of alerts, which will affect the performance of the indexer.

To reduce duplicates, consider one of the following:

- Enable action throttling in the monitor.
- Reduce the query window.
- Add a deduplication mechanism in the Flask script.
- Track processed alert `_id` values in a local state file or database.

## Security notes

- Do not expose port `5000` publicly.
- Bind the webhook only to a trusted interface where possible.
- Restrict access to the webhook using firewall rules.
- Avoid storing Wazuh indexer credentials in shell history.
- Use a non-default Wazuh indexer password.
- Review the Flask script before production use. The built-in Flask server is acceptable for lab testing, but production environments should use a proper WSGI service such as Gunicorn behind a restricted network path.

## Conclusion

This integration uses Wazuh rules, OpenSearch Alerting, a webhook notification channel, and a Python Flask listener to create a summary alert for Fortigate large outbound traffic to public IP addresses. The final alert is generated inside Wazuh, so analysts can view the summarized result directly from the Wazuh dashboard.

## References

- Wazuh integrations repository: https://github.com/wazuh/integrations
- Reference integration structure: https://github.com/wazuh/integrations/tree/main/integrations/gemini_ai-opensearch
- OpenSearch Alerting documentation: https://docs.opensearch.org/latest/observing-your-data/alerting/index/
- OpenSearch Notifications documentation: https://docs.opensearch.org/latest/observing-your-data/notifications/index/
