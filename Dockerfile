FROM golang:1.14-alpine3.12 as builder

RUN apk add --no-cache gcc musl-dev linux-headers binutils git
WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
ARG GOPROXY
ARG GOSUMDB
RUN go mod download

COPY api api/
COPY cmd cmd/
COPY config config/
COPY internal internal/
COPY pkg pkg/
COPY main.go main.go

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o swoll main.go

FROM alpine:3.12

COPY --from=builder /workspace/swoll /usr/local/bin
RUN apk add --no-cache binutils

ENTRYPOINT ["/usr/local/bin/swoll"]
