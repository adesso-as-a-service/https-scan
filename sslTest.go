package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"./hooks"
)

var sslLogger = log.New(hooks.LogWriter, "SSLTest\t", log.Ldate|log.Ltime)

// Tests if a URL is reachable over HTTPS oder HTTP
// 0 unreachable
// 1 http
// 2 https
// 3 http + https
func testHost(host string) uint8 {
	var res uint8
	res = 0
	if testHTTPS(host) {
		res += 2
	}
	if testHTTP(host) {
		res++
	}
	return res
}

func testHTTPS(host string) bool {
	hostName := host
	portNum := "443"
	seconds := 1
	timeOut := time.Duration(seconds) * time.Second
	_, err := net.DialTimeout("tcp", hostName+":"+portNum, timeOut)
	if err != nil {
		if logLevel >= hooks.LogDebug {
			sslLogger.Printf("[DEBUG] Timeout dialing port 443: %v", err)
		}
		return false
	}
	return true
}

func testHTTP(host string) bool {
	hostName := host
	portNum := "80"
	seconds := 1
	timeOut := time.Duration(seconds) * time.Second
	_, err := net.DialTimeout("tcp", hostName+":"+portNum, timeOut)
	if err != nil {
		if logLevel >= hooks.LogDebug {
			sslLogger.Printf("[DEBUG] Timeout dialing port 80: %v", err)
		}
		return false

	}
	return true
}

func testSSL(domain hooks.DomainsRow, channel chan hooks.ScanData) {
	var result hooks.ScanData
	result.DomainID = domain.DomainID
	result.DomainReachable = testHost(domain.DomainName)
	channel <- result
}

// test Reachability of domains. Return unreachable Info and
func runSSLTest(domains []hooks.DomainsRow, scan hooks.ScanRow) ([]hooks.ScanData, hooks.ScanRow, error) {
	currentDomain, domains := domains[0], domains[1:]
	sslChannel := make(chan hooks.ScanData)
	currentScans := 0
	maxScans := 20
	var scanData []hooks.ScanData
	var err error
L:
	for {
		select {
		case res := <-sslChannel:
			if res.DomainReachable != 0 {
				res.ScanID = scan.ScanID
				scanData = append(scanData, res)
			} else {
				scan.Unreachable++
			}
			currentScans--
		case <-time.After(120 * time.Second):
			err := fmt.Errorf("sslTest timed out while waiting for results")
			return scanData, scan, err
		default:
			if currentScans < maxScans {
				currentScans++
				go testSSL(currentDomain, sslChannel)
				if len(domains) > 0 {
					currentDomain, domains = domains[0], domains[1:]
				} else {
					break L
				}
			}
		}
	}
M:
	for {
		select {
		case res := <-sslChannel:
			if res.DomainReachable != 0 {
				res.ScanID = scan.ScanID
				scanData = append(scanData, res)
			} else {
				scan.Unreachable++
				//TODO log unreachable domain
			}
			currentScans--
			if currentScans == 0 {
				break M
			}
		case <-time.After(60 * time.Second):
			err = fmt.Errorf("sslTest timed out while waiting for results")
			return scanData, scan, err
		}
	}
	close(sslChannel)
	scan.Total = len(scanData)
	return scanData, scan, err

}
