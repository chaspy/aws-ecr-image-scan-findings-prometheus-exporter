package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type findingsInfo struct {
	Name       string
	Severity   string
	Attributes []*ecr.Attribute
}

var (
	//nolint:gochecknoglobals
	findings = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "aws_custom",
		Subsystem: "ecr",
		Name:      "image_scan_findings",
		Help:      "ECR Image Scan Findings",
	},
		[]string{"name", "severity", "attributes"},
	)
)

func main() {
	interval, err := getInterval()
	if err != nil {
		log.Fatal(err)
	}

	prometheus.MustRegister(findings)

	http.Handle("/metrics", promhttp.Handler())

	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)

		// register metrics as background
		for range ticker.C {
			err := snapshot()
			if err != nil {
				log.Fatal(err)
			}
		}
	}()
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func snapshot() error {
	findings.Reset()

	findingsInfos, err := getECRImageScanFindings()
	if err != nil {
		return fmt.Errorf("failed to read ECR Image Scan Findings infos: %w", err)
	}

	for _, findingsInfo := range findingsInfos {
		labels := prometheus.Labels{
			"name":       findingsInfo.Name,
			"severity":   findingsInfo.Severity,
			"attributes": "hoge",
			//			"attributes":     findingsInfo.Attributes,
		}
		findings.With(labels).Set(1)
	}

	return nil
}

func getInterval() (int, error) {
	const defaultGithubAPIIntervalSecond = 300
	githubAPIInterval := os.Getenv("AWS_API_INTERVAL")
	if len(githubAPIInterval) == 0 {
		return defaultGithubAPIIntervalSecond, nil
	}

	integerGithubAPIInterval, err := strconv.Atoi(githubAPIInterval)
	if err != nil {
		return 0, fmt.Errorf("failed to read Datadog Config: %w", err)
	}

	return integerGithubAPIInterval, nil
}

func getECRImageScanFindings() ([]findingsInfo, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := ecr.New(sess)
	findingsInfos := []findingsInfo{}

	input := &ecr.DescribeImageScanFindingsInput{
		ImageId:        &ecr.ImageIdentifier{ImageTag: aws.String("develop")},
		RepositoryName: aws.String("api"),
	}

	for {
		findings, err := svc.DescribeImageScanFindings(input)
		if err != nil {
			return nil, fmt.Errorf("failed to describe image scan findings: %w", err)
		}

		results := make([]findingsInfo, len(findings.ImageScanFindings.Findings))
		for i, finding := range findings.ImageScanFindings.Findings {
			results[i] = findingsInfo{
				Name:       aws.StringValue(finding.Name),
				Severity:   aws.StringValue(finding.Severity),
				Attributes: finding.Attributes,
			}
		}

		findingsInfos = append(findingsInfos, results...)

		// Pagination
		if findings.NextToken == nil {
			return findingsInfos, nil
		}
		input.SetNextToken(*findings.NextToken)
	}
}