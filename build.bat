cd %~dp0
rmdir /S /Q bin
mkdir bin
set CGO_ENABLED=0
set GOARCH=amd64
set GOOS=linux
go build -o bin/clashr-linux-amd64
set GOARCH=386
set GOOS=linux
go build -o bin/clashr-linux-386
set GOARCH=amd64
set GOOS=windows
go build -o bin/clashr-windows-amd64.exe
set GOARCH=386
set GOOS=windows
go build -o bin/clashr-windows-386.exe
set GOARCH=amd64
set GOOS=darwin
go build -o bin/clashr-darwin-amd64
set GOARCH=arm64
set GOOS=darwin
go build -o bin/clashr-darwin-arm64
pause