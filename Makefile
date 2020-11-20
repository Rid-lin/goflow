PWD := $(shell pwd)
VERSION := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECTNAME := $(shell basename $(PWD))
GOOS := linux
GOARCH := amd64
# TAG := $(VERSION)_$(GOOS)_$(GOARCH)
TAG := $(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH)
PLATFORMS=darwin linux windows
#ARCHITECTURES=386 amd64
ARCHITECTURES=amd64

# Use linker flags to provide version/build settings
# LDFLAGS=-ldflags "-w -s -X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"
LDFLAGS=-ldflags "-w -s"

.PHONY: build

clean:
	$(shell rm build/$(PROJECTNAME)_*)

build: buildwithoutdebug_linux pack

buildfordebug:
	go build -o build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH).exe -v ./

buildwithoutdebug:
	go build $(LDFLAGS) -o build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH).exe -v ./

buildwodebug_linux:
	set GOOS=linux&&go build $(LDFLAGS) -o build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH) -v ./cmd/

buildwithoutdebug_linux_old:
	@set GOARCH=$(GOARCH)&&set GOOS=$(GOOS)
	@go build $(LDFLAGS) -o build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH) -v ./cmd/

build_linux:
	$(shell export GOOS=linux; export GOARCH=amd64; go build -v $(LDFLAGS) -o build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH) -v ./cmd/)
	upx --ultra-brute build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH)

build_win:
	$(shell export GOOS=windows; export GOARCH=amd64; go build -v $(LDFLAGS) -o build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH).exe -v ./cmd/)
	upx --ultra-brute build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH).exe

prebuild_win:
	$(shell export GOOS=windows; export GOARCH=$(GOARCH); go build -v $(LDFLAGS) -o build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_windows_$(GOARCH).exe -v ./cmd/)
	
prebuild_all:
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); go build -v $(LDFLAGS) -o build/$(PROJECTNAME)__$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH) -v ./cmd/)))
#	$(shell rm build/$(PROJECTNAME)_$(VERSION)_windows_$(GOARCH) build/$(PROJECTNAME)_$(VERSION)_windows_$(GOARCH).exe)

build_all: prebuild_all pack

run: build_win
	build/$(PROJECTNAME)_$(VERSION)_$(BUILD)_$(GOOS)_$(GOARCH).exe
	
.DUFAULT_GOAL := build

pack:
	upx --ultra-brute build/$(PROJECTNAME)_*

mod:
	go mod tidy
	go mod download
	go mod vendor