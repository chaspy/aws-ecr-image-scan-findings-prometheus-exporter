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

## How to run

### Local

```
$ go run main.go
```

### Binary

Get the binary file from [Releases](https://github.com/chaspy/aws-ecr-image-scan-findings-prometheus-exporter/releases) and run it.

### Docker

```
$ docker run chaspy/aws-ecr-image-scan-findings-prometheus-exporter:v0.1.0
```

## Metrics

```
$ curl -s localhost:8080/metrics | grep aws_custom_ecr_image_scan_findings
# HELP aws_custom_ecr_image_scan_findings ECR Image Scan Findings
# TYPE aws_custom_ecr_image_scan_findings gauge
aws_custom_ecr_image_scan_findings{CVSS2_SCORE="9.3",CVSS2_VECTOR="AV:N/AC:M/Au:N/C:C/I:C/A:C",image_tag="production",name="CVE-2019-2201",package_name="1:1.5.2-2",package_version="1:1.5.2-2",repo_name="rails",severity="LOW"} 1
aws_custom_ecr_image_scan_findings{CVSS2_SCORE="9.3",CVSS2_VECTOR="AV:N/AC:M/Au:N/C:C/I:C/A:C",image_tag="production",name="CVE-2019-2201",package_name="1:1.5.2-2",package_version="1:1.5.2-2",repo_name="nginx",severity="LOW"} 1
aws_custom_ecr_image_scan_findings{CVSS2_SCORE="9.3",CVSS2_VECTOR="AV:N/AC:M/Au:N/C:C/I:C/A:C",image_tag="develop",name="CVE-2020-8174",package_name="10.23.0-1nodesource1",package_version="10.23.0-1nodesource1",repo_name="api",severity="CRITICAL"} 1
aws_custom_ecr_image_scan_findings{CVSS2_SCORE="9.3",CVSS2_VECTOR="AV:N/AC:M/Au:N/C:C/I:C/A:C",image_tag="develop",name="CVE-2020-8174",package_name="4.8.2~dfsg-1",package_version="4.8.2~dfsg-1",repo_name="example",severity="CRITICAL"} 1
```

## IAM Role

The following policy must be attached to the AWS role to be executed.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ecr:DescribeRepositories",
                "ecr:DescribeImageScanFindings",
            ],
            "Resource": "*"
        }
    ]
}
```

## Datadog Autodiscovery

If you use Datadog, you can use [Kubernetes Integration Autodiscovery](https://docs.datadoghq.com/agent/kubernetes/integrations/?tab=kubernetes) feature.

