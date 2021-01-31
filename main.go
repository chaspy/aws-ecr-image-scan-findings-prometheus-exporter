package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type findingsInfo struct {
	Name           string
	Severity       string
	PackageVersion string
	PackageName    string
	CVSS2VECTOR    string
	CVSS2SCORE     string
	ImageTag       string
	RepoName       string
}

var (
	//nolint:gochecknoglobals
	findings = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "aws_custom",
		Subsystem: "ecr",
		Name:      "image_scan_findings",
		Help:      "ECR Image Scan Findings",
	},
		[]string{"name", "severity", "package_version", "package_name", "CVSS2_VECTOR", "CVSS2_SCORE", "image_tag", "repo_name"},
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

	repositories, err := getECRRepositories()
	if err != nil {
		return fmt.Errorf("failed to get ECR Repositories: %w", err)
	}

	findingsInfos, err := getECRImageScanFindings(repositories)
	if err != nil {
		return fmt.Errorf("failed to read ECR Image Scan Findings infos: %w", err)
	}

	for _, findingsInfo := range findingsInfos {
		labels := prometheus.Labels{
			"name":            findingsInfo.Name,
			"severity":        findingsInfo.Severity,
			"package_version": findingsInfo.PackageVersion,
			"package_name":    findingsInfo.PackageName,
			"CVSS2_VECTOR":    findingsInfo.CVSS2VECTOR,
			"CVSS2_SCORE":     findingsInfo.CVSS2SCORE,
			"image_tag":       findingsInfo.ImageTag,
			"repo_name":       findingsInfo.RepoName,
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

func getECRImageScanFindings(repositories []string) ([]findingsInfo, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := ecr.New(sess)
	findingsInfos := []findingsInfo{}
	results := []findingsInfo{}

	imageTags, err := getImageTags()
	if err != nil {
		return nil, fmt.Errorf("failed to get image tags: %w", err)
	}

	for _, repo := range repositories {
		for _, imageTag := range imageTags {
			input := &ecr.DescribeImageScanFindingsInput{
				ImageId:        &ecr.ImageIdentifier{ImageTag: aws.String(imageTag)},
				RepositoryName: aws.String(repo),
			}

			for {
				findings, err := svc.DescribeImageScanFindings(input)
				//nolint:gocritic,errorlint
				if aerr, ok := err.(awserr.Error); ok {
					switch aerr.Code() {
					case "ScanNotFoundException":
						log.Printf("Skip the repository %v with imageTag %v. %v\n", repo, imageTag, err.Error())
					case "ImageNotFoundException":
						log.Printf("Skip the repository %v with imageTag %v. %v\n", repo, imageTag, err.Error())
					default:
						return nil, fmt.Errorf("failed to describe image scan findings: %w", err)
					}
				} else if findings.ImageScanFindings == nil {
					log.Printf("Skip the repository %v with imageTag %v. ImageScanStatus: Status %v Description %v\n", repo, imageTag, findings.ImageScanStatus.Status, findings.ImageScanStatus.Description)
				} else {
					results = generateFindingsInfos(findings, imageTag, repo)
				}

				findingsInfos = append(findingsInfos, results...)

				// Pagination
				if findings.NextToken == nil {
					break
				}
				input.SetNextToken(*findings.NextToken)
			}
		}
	}
	return findingsInfos, nil
}

func getImageTags() ([]string, error) {
	imageTags := os.Getenv("IMAGE_TAGS")
	if len(imageTags) == 0 {
		return []string{}, fmt.Errorf("missing environment variable: IMAGE_TAGS")
	}

	imageTagsList := strings.Split(imageTags, ",")
	return imageTagsList, nil
}

func generateFindingsInfos(findings *ecr.DescribeImageScanFindingsOutput, imageTag string, repoName string) []findingsInfo {
	var (
		packageVersion string
		packageName    string
		CVSS2VECTOR    string
		CVSS2SCORE     string
	)

	results := make([]findingsInfo, len(findings.ImageScanFindings.Findings))
	for i, finding := range findings.ImageScanFindings.Findings {
		for _, attr := range finding.Attributes {
			switch *attr.Key {
			case "package_version":
				packageVersion = *attr.Value
			case "package_name":
				packageName = *attr.Value
			case "CVSS2_VECTOR":
				CVSS2VECTOR = *attr.Value
			case "CVSS2_SCORE":
				CVSS2SCORE = *attr.Value
			}
		}
		results[i] = findingsInfo{
			Name:           aws.StringValue(finding.Name),
			Severity:       aws.StringValue(finding.Severity),
			PackageName:    packageName,
			PackageVersion: packageVersion,
			CVSS2VECTOR:    CVSS2VECTOR,
			CVSS2SCORE:     CVSS2SCORE,
			ImageTag:       imageTag,
			RepoName:       repoName,
		}
	}

	return results
}

func getECRRepositories() ([]string, error) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := ecr.New(sess)

	input := &ecr.DescribeRepositoriesInput{}

	result, err := svc.DescribeRepositories(input)
	if err != nil {
		return []string{}, fmt.Errorf("failed to describe repositories: %w", err)
	}

	repositoryNames := make([]string, len(result.Repositories))
	for i, repo := range result.Repositories {
		repositoryNames[i] = *repo.RepositoryName
	}

	return repositoryNames, nil
}
