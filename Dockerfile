# syntax = docker/dockerfile:1.2
FROM golang:1.18 as builder

WORKDIR /src/

ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download -x

COPY . ./
RUN --mount=type=cache,target=/root/.cache/go-build \
	go build -o /vpp-probe

FROM scratch as runtime

COPY --from=builder /vpp-probe /usr/bin/vpp-probe

ENTRYPOINT ["/usr/bin/vpp-probe"]
