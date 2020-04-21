package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"log"
	"net"
	"time"

	"./backend"
	"./hooks"
)

var sslLogger = log.New(hooks.LogWriter, "SSLTest\t", log.Ldate|log.Ltime)

// Tests if a URL is reachable over HTTPS oder HTTP
// 0 unreachable
// 1 http
// 2 https
// 3 http + https
// 4 DNSLookupError
func testHost(host string) uint8 {
	var res uint8
	res = 0
	if !DNSexists(host) {
		return 4
	}
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
		Logger.Debugf("Timeout dialing port 443: %v", err)
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
		Logger.Debugf("Timeout dialing port 80: %v", err)
		return false

	}
	return true
}

// DNSexists checks if there is a domain entry for the host
func DNSexists(host string) bool {
	_, err := net.LookupHost(host)
	if err != nil {
		_, ok := err.(*net.DNSError)
		return !ok
	}
	return true
}

func testSSL(domain hooks.DomainsRow, channel chan hooks.ScanData, scanID int) {
	var result hooks.ScanData
	result.DomainID = domain.DomainID
	result.DomainReachable = testHost(domain.DomainName)
	if result.DomainReachable == 0 || result.DomainReachable == 4 {
		err := backend.SaveUnreachable(scanID, result.DomainID, result.DomainReachable == 4)
		if err != nil {
			Logger.WithFields(logrus.Fields{
				"domainID":   result.DomainID,
				"domainName": domain.DomainName,
				"error":      err,
			}).Error("Failed saving Unreachable-Status")
		}
		result.DomainReachable = 0
	}

	channel <- result
}

// test Reachability of domains. Return unreachable Info and
func runSSLTest(domains []hooks.DomainsRow, scan hooks.ScanRow) ([]hooks.ScanData, hooks.ScanRow, error) {
	currentDomain, domains := domains[0], domains[1:]
	sslChannel := make(chan hooks.ScanData)
	currentScans := 0
	maxScans := 10
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
				go testSSL(currentDomain, sslChannel, scan.ScanID)
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
	scan.Total = len(scanData) + scan.Unreachable
	return scanData, scan, err

}
