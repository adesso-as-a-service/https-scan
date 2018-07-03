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

	log.Fatalf("[ERROR] Unrecognized log level: %v", level)
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
	domains, err := backend.GetDomains()
	if err != nil {
		return scan, err
	}
	scanData, scan, err := runSSLTest(domains[:200], scan)
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
		panic(fmt.Sprintf("Error occurred while reading the config-file 'sql_config.json': %v", err))
	}
	fmt.Printf("Reading SQL Config completed")

	// Opening Database
	err = backend.OpenDatabase(config)
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
				fmt.Printf("%s: Running: %d Remaining: %d, Errors: %d\n", msg.Sender, msg.Status.GetCurrentScans(), msg.Status.GetTotalScans()-msg.Status.GetFinishedScans()-msg.Status.GetErrorScans(), msg.Status.GetErrorScans())
				timeout[msg.Sender] = time.Now()
			} else {
				fmt.Printf("%s is done\n", msg.Sender)
				finished[msg.Sender] = true
			}
		case <-updateTime:
			allDone := true
			for _, manager := range usedManagers {
				allDone = allDone && finished[manager]
				if !finished[manager] && time.Since(timeout[manager]) > time.Duration(5*apis.StatusTime)*time.Second {
					panic(fmt.Sprintf("%s is unreachable, with %d scans remaining\n", manager, hooks.ManagerMap[manager].Status.GetTotalScans()-hooks.ManagerMap[manager].Status.GetFinishedScans()-hooks.ManagerMap[manager].Status.GetErrorScans()))
				}

			}
			if allDone {
				fmt.Printf("Scan is done\n")
				break scan
			}
		}

	}

}
