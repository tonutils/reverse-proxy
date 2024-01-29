GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o build/tonutils-reverse-proxy-linux-amd64 cmd/proxy/main.go
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o build/tonutils-reverse-proxy-linux-arm64 cmd/proxy/main.go
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o build/tonutils-reverse-proxy-windows-x64.exe cmd/proxy/main.go
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o build/tonutils-reverse-proxy-mac-amd64 cmd/proxy/main.go
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o build/tonutils-reverse-proxy-mac-arm64 cmd/proxy/main.go
