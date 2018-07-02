// +build go1.3

/*
 * Includes modified parts from Qualys, Inc. (QUALYS)s ssllabs-scan.
 * ssllabs-scan is released under the the Apache License, Version 2.0
 * (sourcecode @ https://github.com/ssllabs/ssllabs-scan)
 * In accordance with this license, a copy of the license is included
 * in the package.
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"time"
)

// managerMap
var managerMap = map[string]*Manager{
	"Crawler":         &crawlerManager,
	"Observatory":     &obsManager,
	"SecurityHeaders": &sechManager,
	"SSLLabs":         &sslLabsManager,
}

// Diffrent Log-Levels
const (
	logNone     = -1
	logEmerg    = 0
	logAlert    = 1
	logCritical = 2
	logError    = 3
	logWarning  = 4
	logNotice   = 5
	logInfo     = 6
	logDebug    = 7
	logTrace    = 8
)

// reachable
const (
	reachableNot  = 0
	reachableHTTP = 1
	reachableSSL  = 2
	reachableBoth = 3
)

// scanTypes
const (
	scanOnlySSL       = 1
	scanOnlyHTTP      = 2
	scanBoth          = 3
	scanOnePreferSSL  = 4
	scanOnePreferHTTP = 5
)

const (
	statusError   = 255
	statusPending = 0
	statusDone    = 1
	statusIgnored = 2
)

// ScanData contains all the fields needed to create entries in the Scan-Tables
type ScanData struct {
	ScanID          int
	DomainID        int
	DomainReachable uint8
}

// DomainsRow represents a row of the domains Table
type DomainsRow struct {
	DomainID   int
	DomainName string
}

// ScanRow represents a row of the ScanTable
type ScanRow struct {
	ScanID                 int
	SSLLabs                bool
	SSLLabsVersion         string
	Observatory            bool
	ObservatoryVersion     string
	SecurityHeaders        bool
	SecurityHeadersVersion string
	Crawler                bool
	CrawlerVersion         string
	Unreachable            int
	Total                  int
	Done                   bool
}

// logLevel sets the global verbosity of thr Logging
var logLevel int

// parseLogLevel returns the loglevel corresponding to a string
func parseLogLevel(level string) int {
	switch {
	case level == "error":
		return logError
	case level == "notice":
		return logNotice
	case level == "info":
		return logInfo
	case level == "debug":
		return logDebug
	case level == "trace":
		return logTrace
	}

	log.Fatalf("[ERROR] Unrecognized log level: %v", level)
	return -1
}
func getTablenames(usedManagers []string) []string {
	var result []string
	for _, manager := range usedManagers {
		result = append(result, managerMap[manager].getTableName())
	}
	return result
}

// continueScan continues the Scan if possible
func initializeScan(scan ScanRow, usedTables []string) (ScanRow, error) {
	var err error
	scan, err = insertNewScan(scan)
	if err != nil {
		return scan, err
	}
	domains, err := getDomains()
	if err != nil {
		return scan, err
	}
	scanData, scan, err := runSSLTest(domains, scan)
	if err != nil {
		return scan, err
	}
	err = insertScanData(getTablenames(usedTables), scanData)
	if err != nil {
		return scan, err
	}
	err = updateScan(scan)
	return scan, err
}

// continueScan continues the Scan if possible
func continueScan(scan ScanRow) (ScanRow, error) {
	var err error
	var broken string
	scan, err = getLastScan(scan.ScanID)
	if err != nil {
		return scan, err
	}

	if scan.Crawler {
		if managerMap["Crawler"].version != scan.CrawlerVersion {
			broken += "Crawler, "
		}
	}
	if scan.Observatory {
		if managerMap["Observatory"].version != scan.ObservatoryVersion {
			broken += "Observatory, "
		}
	}
	if scan.SSLLabs {
		if managerMap["SSLLabs"].version != scan.SSLLabsVersion {
			broken += "SSLLabs, "
		}
	}
	if scan.SecurityHeaders {
		if managerMap["SecurityHeaders"].version != scan.SecurityHeadersVersion {
			broken += "SecurityHeaders, "
		}
	}

	if broken != "" {
		err = fmt.Errorf("The version for the following Scans has changed in the meantime: %s please start a new Scan", broken)
	}
	return scan, err
}

// Configure scan (Restart/Continue, Select settings(overwrite default), Select scans)
// OpenDatabase
// Monitor Scans (UI)
// run ssltest
// Log better
func main() {
	// Read input arguments
	var confVerbosity = flag.String("verbosity", "info", "Configure log verbosity: error, notice, info, debug, or trace.")
	var confContinue = flag.Int("continue", 0, "continue Scan after error")

	var confSecurityheaders = flag.Bool("no-sechead", false, "Don't use the SecurityHeaders.io-Scan")
	var confSecurityheadersTries = flag.Int("sechead-retries", 3, "Number of retries for the SecurityHeaders.io-Scan")

	var confObservatory = flag.Bool("no-observatory", false, "Don't use the mozilla-observatory-Scan")
	var confObservatoryTries = flag.Int("obs-retries", 3, "Number of retries for the mozilla-observatory-Scan")

	var confSsllabs = flag.Bool("no-ssllabs", false, "Don't use the SSLLabs-Scan")
	var confSsllabsTries = flag.Int("labs-retries", 1, "Number of retries for the sslLabs-Scan")

	var confCrawler = flag.Bool("no-crawler", false, "Don' use the redirect crawler")
	var confCrawlerTries = flag.Int("crawler-retries", 3, "Number of retries for the redirect crawler")
	flag.Parse()

	// Variables
	var err error
	// names of Managers used
	var usedManagers []string
	var currentScan ScanRow

	// configure managers
	logLevel = parseLogLevel(*confVerbosity)

	// create output channel
	outputChannel := make(chan scanStatusMessage)
	timeout := make(map[string]time.Time)
	finished := make(map[string]bool)

	// configuring SecurityHeaders.io-Scan
	currentScan.SecurityHeaders = !*confSecurityheaders
	currentScan.SecurityHeadersVersion = managerMap["SecurityHeaders"].version
	if !*confSecurityheaders {
		if managerMap["SecurityHeaders"].maxParallelScans != 0 {
			managerMap["SecurityHeaders"].maxRetries = *confSecurityheadersTries
			managerMap["SecurityHeaders"].outputChannel = outputChannel
			usedManagers = append(usedManagers, "SecurityHeaders")
		}
	}

	// configuring mozilla-observatory-Scan
	currentScan.Observatory = !*confObservatory
	currentScan.ObservatoryVersion = managerMap["Observatory"].version
	if !*confObservatory {
		if managerMap["Observatory"].maxParallelScans != 0 {
			managerMap["Observatory"].maxRetries = *confObservatoryTries
			managerMap["Observatory"].outputChannel = outputChannel
			usedManagers = append(usedManagers, "Observatory")
		}
	}

	// configuring Ssllabs-Scan
	currentScan.SSLLabs = !*confSsllabs
	currentScan.SSLLabsVersion = managerMap["SSLLabs"].version
	if !*confSsllabs {
		if managerMap["SSLLabs"].maxParallelScans != 0 {
			managerMap["SSLLabs"].maxRetries = *confSsllabsTries
			managerMap["SSLLabs"].outputChannel = outputChannel
			usedManagers = append(usedManagers, "SSLLabs")
		}
	}

	// configuring redirect-crawler
	currentScan.Crawler = !*confCrawler
	currentScan.CrawlerVersion = managerMap["Crawler"].version
	if !*confCrawler {
		if managerMap["Crawler"].maxParallelScans != 0 {
			managerMap["Crawler"].maxRetries = *confCrawlerTries
			managerMap["Crawler"].outputChannel = outputChannel
			usedManagers = append(usedManagers, "Crawler")
		}
	}
	config, err := readSQLConfig("sql_config.json")
	if err != nil {
		panic(fmt.Sprintf("Error occurred while reading the config-file 'sql_config.json': %v", err))
	}
	fmt.Printf("Reading SQL Config completed")

	// Opening Database
	err = openDatabase(config)
	if err != nil {
		panic(fmt.Sprintf("Error occurred while opening the database: %v", err))
	}

	if *confContinue == 0 {
		// create Scan if not continued
		currentScan, err = initializeScan(currentScan, usedManagers)
	} else {
		// continue last or specified
		currentScan.ScanID = *confContinue
		currentScan, err = continueScan(currentScan)

	}
	if err != nil {
		panic(fmt.Sprintf("Error occurred while initializing Scan: %v", err))
		//TODO ErrorHandling
	}

	// start ui

	for _, manager := range usedManagers {
		managerMap[manager].run(currentScan.ScanID, *confContinue != 0)
		timeout[manager] = time.Now()
		finished[manager] = false
	}
	updateTime := time.NewTicker(time.Second * time.Duration(5*statusTime)).C

scan:
	for {
		select {
		case msg := <-outputChannel:
			if msg.status != nil {
				fmt.Printf("%s: Running: %d Remaining: %d, Errors: %d\n", msg.sender, msg.status.getCurrentScans(), msg.status.getTotalScans()-msg.status.getFinishedScans()-msg.status.getErrorScans(), msg.status.getErrorScans())
				timeout[msg.sender] = time.Now()
			} else {
				fmt.Printf("%s is done\n", msg.sender)
				finished[msg.sender] = true
			}
		case <-updateTime:
			allDone := true
			for _, manager := range usedManagers {
				allDone = allDone && finished[manager]
				if !finished[manager] && time.Since(timeout[manager]) > time.Duration(5*statusTime)*time.Second {
					panic(fmt.Sprintf("%s is unreachable, with %d scans remaining\n", manager, managerMap[manager].status.getTotalScans()-managerMap[manager].status.getFinishedScans()-managerMap[manager].status.getErrorScans()))
				}

				if allDone {
					fmt.Printf("Scan is done\n")
					break scan
				}
			}
		}

	}

}
