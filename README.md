# aws-ecr-image-scan-findings-prometheus-exporter
Prometheus Exporter for ECR Image Scan Findings

## Preparation

Copy .envrc.sample to .envrc and load them.

```
$ cp .envrc.sample .envrc
# edit it if needed
# source .envrc
```

|name|default|description|
|----|-------|-----------|
|AWS_API_INTERVAL|300|Duration time to call AWS API (in seconds)|
|IMAGE_TAGS|""|Image Tags of the scan target, separated by comma|
