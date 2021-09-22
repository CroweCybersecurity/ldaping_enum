#!/usr/bin/env bash

##########################
##      Functions       ##
##########################
cmd_exe () {
	eval $@ >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		printf "[\033[32mOK\033[0m]\n"
	else
		printf "[\033[31mFAIL\033[0m]\n"
	fi
}

##########################
##      Variables       ##
##########################
FILE=ldaping_enum.go
ARCH=amd64
OUTPUTFILE=ldaping_enum

printf '\e[1;34m[+]\e[0m Building Linux...'
cmd_exe "GOOS=linux GOARCH=$ARCH go build -o bin/$OUTPUTFILE  $FILE"

printf '\e[1;34m[+]\e[0m Building Windows...'
cmd_exe "GOOS=windows GOARCH=$ARCH go build -o bin/$OUTPUTFILE.exe $FILE"
