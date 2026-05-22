# Welcome to Filebeat 9.3.3

Filebeat sends log files to Logstash or directly to Elasticsearch.

## Getting Started

To get started with Filebeat, you need to set up Elasticsearch on
your localhost first. After that, start Filebeat with:

     ./filebeat -c filebeat.yml -e

This will start Filebeat and send the data to your Elasticsearch
instance. To load the dashboards for Filebeat into Kibana, run:

    ./filebeat setup -e

For further steps visit the
[Quick start](https://www.elastic.co/guide/en/beats/filebeat/9.3/filebeat-installation-configuration.html) guide.

## Documentation

Visit [Elastic.co Docs](https://www.elastic.co/guide/en/beats/filebeat/9.3/index.html)
for the full Filebeat documentation.

## Release notes

https://www.elastic.co/guide/en/beats/libbeat/9.3/release-notes-9.3.3.html
