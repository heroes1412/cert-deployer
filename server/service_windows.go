//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows/svc"
)

type certVaultService struct{}

func (m *certVaultService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[ERROR] Server panic in Windows Service: %v", rec)
			}
		}()
		runServer()
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			break loop
		default:
			log.Printf("Unexpected control request #%d", c.Cmd)
		}
	}
	changes <- svc.Status{State: svc.Stopped}
	return
}

func runWindowsServiceIfService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("[WARN] Failed to check Windows Service mode: %v", err)
		return false
	}

	if isService {
		err = svc.Run("CertVaultServer", &certVaultService{})
		if err != nil {
			log.Printf("[ERROR] Windows Service failed to run: %v", err)
		}
		return true
	}
	return false
}
