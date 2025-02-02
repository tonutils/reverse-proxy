FROM golang:latest AS build

WORKDIR /app
COPY . /app

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-w -s" -o build/tonutils-reverse-proxy cmd/proxy/main.go

FROM gcr.io/distroless/static-debian12

COPY --from=build /app/build/tonutils-reverse-proxy /

ENTRYPOINT [ "/tonutils-reverse-proxy" ]
