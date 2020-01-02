cd %~dp0
set CGO_ENABLED=0
set GOARCH=amd64
set GOOS=linux
go build -mod vendor -o bin/clashr-linux-amd64
set GOARCH=386
set GOOS=linux
go build -mod vendor -o bin/clashr-linux-386
set GOARCH=amd64
set GOOS=windows
go build -mod vendor -o bin/clashr-windows-amd64.exe
set GOARCH=386
set GOOS=windows
go build -mod vendor -o bin/clashr-windows-386.exe
pause