FROM golang:bookworm AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN export DEBCONF_NONINTERACTIVE_SEEN=true \
    DEBIAN_FRONTEND=noninteractive \
    DEBIAN_PRIORITY=critical \
    TERM=linux ; \
    apt-get -qq update ; \
    apt-get -yyqq upgrade ; \
    apt-get -yyqq install ca-certificates && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-w -s" -o build/tonutils-reverse-proxy cmd/proxy/main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /app/build/tonutils-reverse-proxy /
USER nonroot:nonroot
WORKDIR /
ENTRYPOINT [ "/tonutils-reverse-proxy" ]
