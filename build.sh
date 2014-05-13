#!/bin/sh
echo "start building..."
echo "    >>> build app-cli.go"
go build app-cli.go 
echo "    <<< build succeed"
echo "    >>> build devsmart.go"
go build devsmart.go
echo "    <<< build succeed"
echo "build all down"
