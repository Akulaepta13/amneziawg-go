//go:build android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2025 Amnezia VPN. All Rights Reserved.
 */

package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

var (
	tunnelHandles = make(map[int32]*device.Device)
	tunnelMutex   sync.Mutex
	nextHandle    int32 = 1
)

func init() {
	// Android log tag
	tag := C.CString("AmneziaWG-Go")
	msg := C.CString("Library loaded and initialized correctly")
	// Use __android_log_print directly if possible, but we don't have it imported in CGO.
	// Just rely on the fact that this code is compiled.
	_ = tag
	_ = msg
}

//export wgTest
func wgTest() C.int {
	return 123
}

//export wgTurnOn
func wgTurnOn(configStr *C.char, tunFd C.int) C.int {
	goConfig := C.GoString(configStr)
	fd := int(tunFd)

	// Create TUN device from file descriptor using Android-compatible function
	tunDevice, tunName, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		return -1
	}
	_ = tunName // unused but returned by the function

	// Create logger
	logger := device.NewLogger(
		device.LogLevelVerbose,
		"(AmneziaWG) ",
	)

	// Create WireGuard device
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// Apply configuration
	err = dev.IpcSet(goConfig)
	if err != nil {
		dev.Close()
		return -2
	}

	// Bring device up
	err = dev.Up()
	if err != nil {
		dev.Close()
		return -3
	}

	// Store handle
	tunnelMutex.Lock()
	handle := nextHandle
	nextHandle++
	tunnelHandles[handle] = dev
	tunnelMutex.Unlock()

	return C.int(handle)
}

//export wgTurnOff
func wgTurnOff(tunnelHandle C.int) {
	handle := int32(tunnelHandle)

	tunnelMutex.Lock()
	dev, ok := tunnelHandles[handle]
	if ok {
		delete(tunnelHandles, handle)
	}
	tunnelMutex.Unlock()

	if ok && dev != nil {
		dev.Close()
	}
}

//export wgGetConfig
func wgGetConfig(tunnelHandle C.int) *C.char {
	handle := int32(tunnelHandle)

	tunnelMutex.Lock()
	dev, ok := tunnelHandles[handle]
	tunnelMutex.Unlock()

	if !ok || dev == nil {
		return nil
	}

	// Get configuration from device
	config, err := dev.IpcGet()
	if err != nil {
		return nil
	}

	return C.CString(config)
}

//export wgGetSocketV4
func wgGetSocketV4(tunnelHandle C.int) C.int {
	handle := int32(tunnelHandle)

	tunnelMutex.Lock()
	dev, ok := tunnelHandles[handle]
	tunnelMutex.Unlock()

	if !ok || dev == nil {
		return -1
	}

	bind, ok := dev.Bind().(conn.PeekLookAtSocketFd)
	if !ok {
		return -1
	}

	fd, err := bind.PeekLookAtSocketFd4()
	if err != nil {
		return -1
	}
	return C.int(fd)
}

//export wgGetSocketV6
func wgGetSocketV6(tunnelHandle C.int) C.int {
	handle := int32(tunnelHandle)

	tunnelMutex.Lock()
	dev, ok := tunnelHandles[handle]
	tunnelMutex.Unlock()

	if !ok || dev == nil {
		return -1
	}

	bind, ok := dev.Bind().(conn.PeekLookAtSocketFd)
	if !ok {
		return -1
	}

	fd, err := bind.PeekLookAtSocketFd6()
	if err != nil {
		return -1
	}
	return C.int(fd)
}

//export wgVersion
func wgVersion() *C.char {
	return C.CString("amneziawg-go " + Version)
}

//export wgFreeString
func wgFreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

// ConvertToUAPIConfig converts simplified config format to UAPI format
func ConvertToUAPIConfig(config string) (string, error) {
	var result strings.Builder
	lines := strings.Split(config, "\n")

	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "[Interface]" {
			currentSection = "interface"
			continue
		}
		if line == "[Peer]" {
			currentSection = "peer"
			result.WriteString("public_key=")
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "interface":
			switch strings.ToLower(key) {
			case "privatekey":
				result.WriteString("private_key=")
				result.WriteString(value)
				result.WriteString("\n")
			}
		case "peer":
			switch strings.ToLower(key) {
			case "publickey":
				result.WriteString(value)
				result.WriteString("\n")
			case "presharedkey":
				result.WriteString("preshared_key=")
				result.WriteString(value)
				result.WriteString("\n")
			case "endpoint":
				result.WriteString("endpoint=")
				result.WriteString(value)
				result.WriteString("\n")
			case "allowedips":
				for _, ip := range strings.Split(value, ",") {
					result.WriteString("allowed_ip=")
					result.WriteString(strings.TrimSpace(ip))
					result.WriteString("\n")
				}
			case "persistentkeepalive":
				result.WriteString("persistent_keepalive_interval=")
				result.WriteString(value)
				result.WriteString("\n")
			// AmneziaWG specific parameters
			case "jc":
				result.WriteString("jc=")
				result.WriteString(value)
				result.WriteString("\n")
			case "jmin":
				result.WriteString("jmin=")
				result.WriteString(value)
				result.WriteString("\n")
			case "jmax":
				result.WriteString("jmax=")
				result.WriteString(value)
				result.WriteString("\n")
			case "s1":
				result.WriteString("s1=")
				result.WriteString(value)
				result.WriteString("\n")
			case "s2":
				result.WriteString("s2=")
				result.WriteString(value)
				result.WriteString("\n")
			case "h1":
				result.WriteString("h1=")
				result.WriteString(value)
				result.WriteString("\n")
			case "h2":
				result.WriteString("h2=")
				result.WriteString(value)
				result.WriteString("\n")
			case "h3":
				result.WriteString("h3=")
				result.WriteString(value)
				result.WriteString("\n")
			case "h4":
				result.WriteString("h4=")
				result.WriteString(value)
				result.WriteString("\n")
			}
		}
	}

	if result.Len() == 0 {
		return "", errors.New("empty configuration")
	}

	return result.String(), nil
}
