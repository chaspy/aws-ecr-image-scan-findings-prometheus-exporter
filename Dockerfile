FROM golang:1.20.5 as builder

WORKDIR /go/src

COPY go.mod go.sum ./
RUN go mod download

COPY ./main.go  ./

ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64
RUN go build \
    -o /go/bin/aws-ecr-image-scan-findings-prometheus-exporter \
    -ldflags '-s -w'

FROM alpine:3.18.2 as runner

COPY --from=builder /go/bin/aws-ecr-image-scan-findings-prometheus-exporter /app/aws-ecr-image-scan-findings-prometheus-exporter

RUN adduser -D -S -H exporter

USER exporter

ENTRYPOINT ["/app/aws-ecr-image-scan-findings-prometheus-exporter"]
