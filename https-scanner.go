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
	"strings"
	"time"

	"./apis"
	"./backend"
	"./hooks"
)

// logLevel sets the global verbosity of thr Logging
var logLevel int

var logger = log.New(hooks.LogWriter, "Control\t", log.Ldate|log.Ltime)
var infoLogger = log.New(hooks.LogWriter, "", 0)

// parseLogLevel returns the loglevel corresponding to a string
func parseLogLevel(level string) int {
	switch {
	case level == "error":
		return hooks.LogError
	case level == "notice":
		return hooks.LogNotice
	case level == "info":
		return hooks.LogInfo
	case level == "debug":
		return hooks.LogDebug
	case level == "trace":
		return hooks.LogTrace
	}

	logger.Fatalf("[ERROR] Unrecognized log level: %v", level)
	return -1
}
func getTablenames(usedManagers []string) []string {
	var result []string
	for _, manager := range usedManagers {
		man := hooks.ManagerMap[manager]
		result = append(result, man.GetTableName())
	}
	return result
}

// continueScan continues the Scan if possible
func initializeScan(scan hooks.ScanRow, usedTables []string) (hooks.ScanRow, error) {
	var err error
	scan, err = backend.InsertNewScan(scan)
	if err != nil {
		return scan, err
	}
	infoLogger.Printf("---------------------------------------------------------------------------------------------------\nStarting Scan with ScanID %d\n---------------------------------------------------------------------------------------------------", scan.ScanID)
	domains, err := backend.GetDomains()
	if err != nil {
		return scan, err
	}
	scanData, scan, err := runSSLTest(domains[:100], scan)
	if err != nil {
		return scan, err
	}
	err = backend.InsertScanData(getTablenames(usedTables), scanData)
	if err != nil {
		return scan, err
	}
	err = backend.UpdateScan(scan)
	return scan, err
}

// continueScan continues the Scan if possible
func continueScan(scan hooks.ScanRow) (hooks.ScanRow, error) {
	var err error
	var broken []string
	scan, err = backend.GetLastScan(scan.ScanID)
	if err != nil {
		return scan, err
	}

	for tableName, f := range hooks.ContinueScan {
		if !f(scan) {
			broken = append(broken, tableName)
		}
	}

	if len(broken) != 0 {
		err = fmt.Errorf("The version for the following Scans have changed in the meantime: %s! Please start a new Scan", strings.Join(broken, ", "))
	}
	infoLogger.Printf("---------------------------------------------------------------------------------------------------\nContinueing Scan with ScanID %d\n---------------------------------------------------------------------------------------------------", scan.ScanID)
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
	var confContinue = flag.Int("continue", 0, "continue Scan with given ID after error (-1 for latest scan) ")

	// setUp Input Arguments for apis
	for _, f := range hooks.FlagSetUp {
		f()
	}

	flag.Parse()

	// Variables
	var err error
	// names of Managers used
	var usedManagers []string
	var currentScan hooks.ScanRow

	// configure managers
	logLevel = parseLogLevel(*confVerbosity)
	// set log level for all managers
	for _, man := range hooks.ManagerMap {
		man.LogLevel = logLevel
	}

	// create output channel
	outputChannel := make(chan hooks.ScanStatusMessage)
	timeout := make(map[string]time.Time)
	finished := make(map[string]bool)

	// configuring Apis and set used managers
	for tableName, f := range hooks.ConfigureSetUp {
		if f(&currentScan, outputChannel) {
			usedManagers = append(usedManagers, tableName)
		}
	}

	config, err := backend.ReadSQLConfig("sql_config.json")
	if err != nil {
		logger.Fatalf("Error occurred while reading the config-file 'sql_config.json': %v", err)
	}
	infoLogger.Println("Reading SQL Config completed")

	// Opening Database
	err = backend.OpenDatabase(config)
	if err != nil {
		logger.Fatalf("Error occurred while opening the database: %v", err)
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
		logger.Fatalf("Error occurred while initializing Scan: %v", err)
	}

	// start ui

	for _, manager := range usedManagers {
		apis.Start(hooks.ManagerMap[manager], currentScan.ScanID, *confContinue != 0)
		timeout[manager] = time.Now()
		finished[manager] = false
	}
	updateTime := time.NewTicker(time.Second * time.Duration(5*apis.StatusTime)).C

scan:
	for {
		select {
		case msg := <-outputChannel:
			if msg.Status != nil {
				hooks.LogIfNeeded(logger, fmt.Sprintf("Received status message from %v", msg.Sender), logLevel, hooks.LogDebug)
				timeout[msg.Sender] = time.Now()
			} else {
				hooks.LogIfNeeded(logger, fmt.Sprintf("Received 'finished' message from %v", msg.Sender), logLevel, hooks.LogDebug)
				finished[msg.Sender] = true
			}
		case <-updateTime:
			allDone := true
			for _, manager := range usedManagers {
				allDone = allDone && finished[manager]
				if !finished[manager] && time.Since(timeout[manager]) > time.Duration(5*apis.StatusTime)*time.Second {
					logger.Fatalf("Manager %s has been unreachable fo %d seconds", manager, 5*apis.StatusTime)
				}

			}
			if allDone {
				infoLogger.Printf("---------------------------------------------------------------------------------------------------\nScan with ScanID %d is done\n---------------------------------------------------------------------------------------------------", currentScan.ScanID)
				break scan
			}
		}

	}

}
