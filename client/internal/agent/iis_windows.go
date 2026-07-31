//go:build windows

package agent

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func ImportPFXAndRebindIIS(pfxPath, password, siteName, bindingHost string) error {
	// Escape arguments for PowerShell script execution
	escapedPfx := strings.ReplaceAll(pfxPath, "'", "''")
	escapedPass := strings.ReplaceAll(password, "'", "''")
	escapedSite := strings.ReplaceAll(siteName, "'", "''")
	escapedHost := strings.ReplaceAll(bindingHost, "'", "''")

	psScript := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'

# 1. Import PFX Certificate into Cert:\LocalMachine\My
if ('%s' -ne '') {
    $secPass = ConvertTo-SecureString '%s' -AsPlainText -Force
    $cert = Import-PfxCertificate -FilePath '%s' -CertStoreLocation Cert:\LocalMachine\My -Password $secPass
} else {
    $cert = Import-PfxCertificate -FilePath '%s' -CertStoreLocation Cert:\LocalMachine\My
}

$thumbprint = $cert.Thumbprint.Trim().ToUpper()
Write-Host "Imported new cert thumbprint: $thumbprint"

# 2. Load IIS WebAdministration Module
Import-Module WebAdministration

$siteName = '%s'
$rawHost = '%s'
$targetHost = $rawHost
$specifiedPort = ''

if ($rawHost -like '*:*') {
    $parts = $rawHost -split ':'
    $targetHost = $parts[0]
    $specifiedPort = $parts[1]
}

# 3. Get existing HTTPS bindings for the site
$bindings = Get-WebBinding -Name $siteName -Protocol 'https'

# Check if matching HTTPS binding exists by parsing bindingInformation string directly!
$matchingFound = $false
if ($bindings) {
    foreach ($b in $bindings) {
        $infoParts = $b.bindingInformation -split ':'
        $portNum = if ($infoParts.Length -ge 2) { $infoParts[1] } else { '443' }
        $hostHeader = if ($infoParts.Length -ge 3) { $infoParts[2] } else { '' }

        $matchHost = ($targetHost -eq '' -or $hostHeader -eq $targetHost)
        $matchPort = ($specifiedPort -eq '' -or $portNum -eq $specifiedPort)

        if ($matchHost -and $matchPort) {
            $matchingFound = $true
        }
    }
}

# Case 1: First time run - Create new HTTPS binding if missing
if (-not $matchingFound) {
    $createPort = if ($specifiedPort -ne '') { [int]$specifiedPort } else { 443 }
    Write-Host "No matching HTTPS binding found for site '$siteName' (Host: '$targetHost', Port: $createPort). Creating new binding..."
    try {
        if ($targetHost -ne '') {
            New-WebBinding -Name $siteName -Protocol 'https' -Port $createPort -HostHeader $targetHost -SslFlags 1 -ErrorAction SilentlyContinue
        } else {
            New-WebBinding -Name $siteName -Protocol 'https' -Port $createPort -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "New-WebBinding notice: $_"
    }
    # Re-fetch bindings
    $bindings = Get-WebBinding -Name $siteName -Protocol 'https'
}

# Case 2: Update all matching HTTPS bindings
if ($bindings) {
    foreach ($b in $bindings) {
        $infoParts = $b.bindingInformation -split ':'
        $ipAddr = if ($infoParts.Length -ge 1 -and $infoParts[0] -ne '*' -and $infoParts[0] -ne '') { $infoParts[0] } else { '0.0.0.0' }
        $portNum = if ($infoParts.Length -ge 2) { $infoParts[1] } else { '443' }
        $hostHeader = if ($infoParts.Length -ge 3) { $infoParts[2] } else { '' }

        $matchHost = ($targetHost -eq '' -or $hostHeader -eq $targetHost)
        $matchPort = ($specifiedPort -eq '' -or $portNum -eq $specifiedPort)

        if ($matchHost -and $matchPort) {
            Write-Host "Updating IIS SSL Binding for '$siteName' -> Host: '$hostHeader', Port: $portNum to Thumbprint: $thumbprint"

            # A. Update IIS binding certificateHash & certificateStoreName via Set-WebBinding cmdlet
            try {
                if ($hostHeader -ne '') {
                    Set-WebBinding -Name $siteName -HostHeader $hostHeader -Port $portNum -PropertyName "certificateHash" -Value $thumbprint -ErrorAction SilentlyContinue
                    Set-WebBinding -Name $siteName -HostHeader $hostHeader -Port $portNum -PropertyName "certificateStoreName" -Value "my" -ErrorAction SilentlyContinue
                } else {
                    Set-WebBinding -Name $siteName -IPAddress $ipAddr -Port $portNum -PropertyName "certificateHash" -Value $thumbprint -ErrorAction SilentlyContinue
                    Set-WebBinding -Name $siteName -IPAddress $ipAddr -Port $portNum -PropertyName "certificateStoreName" -Value "my" -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Host "Set-WebBinding notice: $_"
            }

            # B. AddSslCertificate via binding object
            try { $b.RemoveSslCertificate() } catch {}
            try {
                $b.AddSslCertificate($thumbprint, "my")
                Write-Host "AddSslCertificate executed successfully."
            } catch {
                Write-Host "AddSslCertificate notice: $_"
            }

            # C. Update HTTP.sys kernel SSL table via netsh http
            if ($b.sslFlags -gt 0 -or $hostHeader -ne '') {
                & netsh http delete sslcert hostnameport="${hostHeader}:${portNum}" 2>&1 | Out-Null
                $res = & netsh http add sslcert hostnameport="${hostHeader}:${portNum}" certhash=$thumbprint appid='{4dc3e828-0808-410b-9674-06513b63bbf3}' certstorename=MY 2>&1
                Write-Host "netsh hostnameport ${hostHeader}:${portNum} output: $res"
            } else {
                & netsh http delete sslcert ipport="${ipAddr}:${portNum}" 2>&1 | Out-Null
                $res = & netsh http add sslcert ipport="${ipAddr}:${portNum}" certhash=$thumbprint appid='{4dc3e828-0808-410b-9674-06513b63bbf3}' certstorename=MY 2>&1
                Write-Host "netsh ipport ${ipAddr}:${portNum} output: $res"
            }
        }
    }
}
`, escapedPass, escapedPass, escapedPfx, escapedPfx, escapedSite, escapedHost)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("IIS import/rebind failed: %v, output: %s", err, string(out))
	}

	if len(out) > 0 {
		fmt.Printf("[%s] [INFO] IIS Output:\n%s\n", time.Now().Format("2006-01-02 15:04:05"), string(out))
	}

	fmt.Printf("[%s] [INFO] IIS SSL Certificate imported & rebound successfully for site: %s\n", time.Now().Format("2006-01-02 15:04:05"), siteName)
	return nil
}
