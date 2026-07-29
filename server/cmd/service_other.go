//go:build !windows

package main

func runWindowsServiceIfService() bool {
	return false
}
