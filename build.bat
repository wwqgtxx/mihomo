cd %~dp0
rmdir /S /Q bin
mkdir bin
set CGO_ENABLED=0
set GOTOOLCHAIN=local
set GOARCH=amd64
set GOOS=linux
go build -tags with_gvisor -o bin/mihomo-linux-amd64
set GOARCH=386
set GOOS=linux
go build -tags with_gvisor -o bin/mihomo-linux-386
set GOARCH=amd64
set GOOS=windows
go build -tags with_gvisor -o bin/mihomo-windows-amd64.exe
set GOARCH=386
set GOOS=windows
go build -tags with_gvisor -o bin/mihomo-windows-386.exe
set GOARCH=amd64
set GOOS=darwin
go build -tags with_gvisor -o bin/mihomo-darwin-amd64
set GOARCH=arm64
set GOOS=darwin
go build -tags with_gvisor -o bin/mihomo-darwin-arm64
set GOARCH=
set GOMIPS=
set GOOS=
pause