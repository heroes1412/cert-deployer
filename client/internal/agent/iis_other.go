//go:build !windows

package agent

import "fmt"

func ImportPFXAndRebindIIS(pfxPath, password, siteName, bindingHost string) error {
	return fmt.Errorf("IIS Store Import is only supported on Windows operating systems")
}
