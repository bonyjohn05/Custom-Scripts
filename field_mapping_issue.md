# Configure Wazuh Filebeat Pipeline to Avoid Field Mapping Conflicts

## Overview

This guide explains how to modify the Wazuh Filebeat ingest pipeline to prevent field mapping conflicts in Wazuh indexer.
Specifically, it demonstrates how to rename fields such as data.port when the alert belongs to a specific rule group (e.g., postgresql).

## Alert Processing Flow
Event → Wazuh Manager → alerts.json → Filebeat → pipeline.json → wazuh-template.json → Indexer

Filebeat parses alerts through the ingest pipeline before indexing them into Wazuh indexer.
We’ll update the pipeline.json to conditionally rename and convert fields to avoid mapping conflicts.

## Example Rule

Here’s a sample rule that triggers alerts containing the rule.groups value postgresql:
```bash
<group name="postgresql,">
    <rule id="100020" level="3">
      <decoded_as>json</decoded_as>
      <field name="service">postgresql</field>
      <description>User: $(jump_username) $(message)</description>
    </rule>
</group>
```

The alert triggers when a JSON-decoded event contains "service": "postgresql".
The rule.groups field will include postgresql, which we’ll use as a condition in our pipeline.

### Steps to Avoid Field Mapping Conflict Issues While Indexing on wazuh-alerts Index
1. Backup the existing pipeline file:
```bash
cp /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json /tmp/pipeline.json
```

2. Open the pipeline file:
```bash
vi /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json
```

3. Locate the processors section, and insert the following snippet after the "date_index_name" section and before the first remove block.
```bash
{
  "rename": {
    "field": "data.port",
    "target_field": "data.port_number",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); def v = ctx?.data?.port; return isPg && v != null && !(v instanceof Map);"
  }
},
{
  "convert": {
    "field": "data.port_number",
    "type": "long",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); return isPg;"
  }
},
{
  "remove": {
    "field": "data.port",
    "ignore_missing": true,
    "if": "def v = ctx?.data?.port; return v != null && !(v instanceof Map);"
  }
},
```

**Example Pipeline Section**
Your pipeline section should look like this:
```bash
  {
      "date_index_name": {
        "field": "timestamp",
        "date_rounding": "d",
        "index_name_prefix": "{{fields.index_prefix}}",
        "index_name_format": "yyyy.MM.dd",
        "ignore_failure": false
      }
    },
    {
  "rename": {
    "field": "data.port",
    "target_field": "data.port_number",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); def v = ctx?.data?.port; return isPg && v != null && !(v instanceof Map);"
  }
},
{
  "convert": {
    "field": "data.port_number",
    "type": "long",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); return isPg;"
  }
},
{
  "remove": {
    "field": "data.port",
    "ignore_missing": true,
    "if": "def v = ctx?.data?.port; return v != null && !(v instanceof Map);"
  }
},
    { "remove": { "field": "message", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "ecs", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "beat", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "input_type", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "tags", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "count", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "@version", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "log", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "offset", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "type", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "host", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "fields", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "event", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "fileset", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "service", "ignore_missing": true, "ignore_failure": true } }
  ],
```

4. Save the configuration and apply the pipeline:
```bash
filebeat setup --pipelines
systemctl restart filebeat
```
After applying this configuration:
- Alerts with `rule.groups`: `postgresql` will have `data.port` renamed to `data.port_number`.
- Indexing conflicts will be avoided, and data will appear properly in dashboards.

<img width="945" height="831" alt="image" src="https://github.com/user-attachments/assets/7c195da0-eb07-47b2-870d-bfcff2c41f50" />


## Note on Archives Index

By default, this fix applies only to the alerts pipeline.
To ensure consistent indexing in the archives index, you must apply similar modifications to:
```bash
/usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json
```

1. Backup the existing archives pipeline file:
```bash
cp /usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json /tmp/archives-pipeline.json
```

2. Open the pipeline file:
```bash
vi /usr/share/filebeat/module/wazuh/archives/ingest/pipeline.json
```

3. Locate the processors section, and insert the following snippet after the "date_index_name" section and before the first remove block.
```bash
{
  "rename": {
    "field": "data.port",
    "target_field": "data.port_number",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); def v = ctx?.data?.port; return isPg && v != null && !(v instanceof Map);"
  }
},
{
  "convert": {
    "field": "data.port_number",
    "type": "long",
    "ignore_missing": true
  }
},
{
  "remove": {
    "field": "data.port",
    "ignore_missing": true,
    "if": "def v = ctx?.data?.port; return v != null && !(v instanceof Map);"
  }
},
{
  "rename": {
    "field": "data.service",
    "target_field": "data.service_name",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); def v = ctx?.data?.service; return isPg && v != null && !(v instanceof Map);"
  }
},
{
  "remove": {
    "field": "data.service",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); def v = ctx?.data?.service; return isPg && v != null && !(v instanceof Map);"
  }
},
```

**Example Pipeline Section**
Your pipeline section should look like this:
```bash
    {
      "date_index_name": {
        "field": "timestamp",
        "date_rounding": "d",
        "index_name_prefix": "{{fields.index_prefix}}",
        "index_name_format": "yyyy.MM.dd",
        "ignore_failure": false
      }
    },
    {
  "rename": {
    "field": "data.port",
    "target_field": "data.port_number",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); def v = ctx?.data?.port; return isPg && v != null && !(v instanceof Map);"
  }
},
{
  "convert": {
    "field": "data.port_number",
    "type": "long",
    "ignore_missing": true
  }
},
{
  "remove": {
    "field": "data.port",
    "ignore_missing": true,
    "if": "def v = ctx?.data?.port; return v != null && !(v instanceof Map);"
  }
},
{
  "rename": {
    "field": "data.service",
    "target_field": "data.service_name",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); def v = ctx?.data?.service; return isPg && v != null && !(v instanceof Map);"
  }
},
{
  "remove": {
    "field": "data.service",
    "ignore_missing": true,
    "if": "def g = ctx?.rule?.groups; def isPg = g != null && ((g instanceof List && g.contains('postgresql')) || (g instanceof String && g == 'postgresql')); def v = ctx?.data?.service; return isPg && v != null && !(v instanceof Map);"
  }
},
    { "remove": { "field": "message", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "ecs", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "beat", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "input_type", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "tags", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "count", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "@version", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "log", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "offset", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "type", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "host", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "fields", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "event", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "fileset", "ignore_missing": true, "ignore_failure": true } },
    { "remove": { "field": "service", "ignore_missing": true, "ignore_failure": true } }
  ],
```

4. Save the configuration and apply the pipeline:
```bash
filebeat setup --pipelines
systemctl restart filebeat
```
Now, both alerts and archives indices will store the data without field mapping conflicts.

<img width="1930" height="1615" alt="image" src="https://github.com/user-attachments/assets/f0cb1334-96b1-4926-af94-1e65d0f42ac5" />

## Result
- Alerts appear correctly in the Threat Hunting and Wazuh Alerts dashboards.
- Mapping conflicts related to data.port and data.service are resolved.
- Archives indexing works properly after the same processors are applied.
