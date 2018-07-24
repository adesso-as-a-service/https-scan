/*
 * Includes modified parts from Qualys, Inc. (QUALYS)s ssllabs-scan.
 * ssllabs-scan is released under the the Apache License, Version 2.0
 * (sourcecode @ https://github.com/ssllabs/ssllabs-scan)
 * In accordance with this license, a copy of the license is included
 * in the package.
 */

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
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
var forceOverwrite bool

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
	scanData, scan, err := runSSLTest(domains, scan)
	if err != nil {
		return scan, err
	}
	if len(scanData) == 0 {
		backend.UpdateScan(scan)
		logger.Fatal("There are no domains left to scan after a reachability test!")
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

func conflictAdd(domains []string, list string) error {
	conflicts := backend.GetConflictingDomains(domains, list)
	domainStruct := make([]hooks.DomainsRowMetaInfo, 0, len(domains))
	currentPos := 0
	var helpStruct hooks.DomainsRowMetaInfo
	for _, dom := range domains {
		domainStruct = domainStruct[:currentPos+1]
		conflict := conflicts[dom]
		helpStruct.DomainName = dom
		helpStruct.ListID.String = list
		helpStruct.ListID.Valid = true
		helpStruct.IsActive = true
		if conflict.DomainName == "" {
			domainStruct[currentPos] = helpStruct
			currentPos++
		} else {
			fmt.Printf("Conflicting Entries:\n\tOld: Domain: %s\tListID: %s\tActive: %b\n\tNew: Domain: %s\tListID: %s\tActive: %v\n",
				conflict.DomainName, conflict.ListID.String, conflict.IsActive, helpStruct.DomainName, helpStruct.ListID.String, helpStruct.IsActive)
			// read user input
			if forceOverwrite {
				domainStruct[currentPos] = helpStruct
				currentPos++
			} else {
				reader := bufio.NewReader(os.Stdin)
			loop:
				for {
					fmt.Print("O to overwrite / S to skip [O/S]: ")
					choice, _ := reader.ReadString('\n')
					choice = strings.Trim(choice, " \t")
					switch choice[0] {
					case 'O':
						domainStruct[currentPos] = helpStruct
						currentPos++
						break loop
					case 'S':
						break loop
					}
				}
			}
		}
	}
	return backend.UpdateDomainsFull(domainStruct)
}

func parseSettings(list string, file string, domain string, scan bool, add bool, remove bool, inactive bool, active bool) (bool, error) {
	if add && remove {
		return false, fmt.Errorf("Can't -remove and -add at the same time")
	}
	if active && inactive {
		return false, fmt.Errorf("Can't set Domains to active and inactive at the same time")
	}

	if remove && list == "" {
		return false, fmt.Errorf("For -add and -remove actions a ListID needs to be given")
	}

	if scan && (active || inactive) {
		return false, fmt.Errorf("Can't scan and set addresses active/inactive at once")
	}

	if scan && add {
		return false, fmt.Errorf("Can't scan and add addresses inactive at once")
	}

	if scan && remove {
		return false, fmt.Errorf("Can't scan and remove addresses inactive at once")
	}
	var domains []string
	var err error
	if file != "" {
		domains, err = readLines(&file)
		if err != nil {
			return false, err
		}
	}

	if domain != "" {
		domains = append(domains, parseDomain(domain))
	}
	err = backend.ResetDomains()
	if err != nil {
		return false, err
	}

	if len(domains) == 0 && list == "" {
		return false, fmt.Errorf("No domains or ListID have been specified")
	} else if len(domains) == 0 {
		if add {
			return false, fmt.Errorf("Adding List: %s to List: %s makes no sense", list, list)
		}
		if inactive {
			err := backend.ActiveDomainsWithListID(false, list)
			return false, err
		}
		if active {
			// set all listID to active return false
			err := backend.ActiveDomainsWithListID(true, list)
			return false, err
		}

		if remove {
			// delete all ListIDs return false
			err := backend.RemoveDomainsWithListID(list)
			return false, err
		}
		if scan {
			// set up scan and return true
			err := backend.ScanDomainsWithListID(list)
			return true, err
		}
	} else if list == "" {
		if inactive {
			// set all domains to inactive return false
			for _, dom := range domains {
				err := backend.ActiveDomainsWithDomain(false, dom)
				if err != nil {
					break
				}
			}

			return false, err
		}
		if active {
			// set all domains to active return false
			for _, dom := range domains {
				err := backend.ActiveDomainsWithDomain(true, dom)
				if err != nil {
					break
				}
			}

			return false, err
		}
		if remove {
			// delete all ListIDs return false
			for _, dom := range domains {
				err := backend.RemoveDomainsWithDomain(dom)
				if err != nil {
					break
				}
			}

			return false, err
		}
		if scan {
			for _, dom := range domains {
				err := backend.ScanDomainsWithDomain(dom)
				if err != nil {
					break
				}
			}
			return true, err
		}

	} else {
		if inactive || active {
			return false, fmt.Errorf("Combing domains with ListID and -active or -inactive is not possible")
		}

		if add {
			err := conflictAdd(domains, list)
			return false, err
		}

		if remove {
			// remove domains from ListID
			for _, dom := range domains {
				err := backend.RemoveDomainsWithDomainAndList(dom, list)
				if err != nil {
					break
				}
			}
			return false, err
		}
		if scan {
			// set nextScan to true
			for _, dom := range domains {
				err := backend.ScanDomainsWithDomain(dom)
				if err != nil {
					break
				}
			}
			if err != nil {
				return false, err
			}
			err := backend.ScanDomainsWithListID(list)
			return true, err
		}
	}
	return false, fmt.Errorf("Unknown commandline argument combination")

}

// Configure scan (Restart/Continue, Select settings(overwrite default), Select scans)
// OpenDatabase
// Monitor Scans (UI)
// run ssltest
// Log better
func main() {
	// Read input arguments
	var confVerbosity = flag.String("verbosity", "info", "Configure log verbosity: error, notice, info, debug, or trace.")
	var confContinue = flag.Bool("continue", false, "Continue the last scan ")

	var confList = flag.String("list", "", "Specify a ListID for domains.")
	var confFile = flag.String("file", "", "Specify a file to be read for domains.")
	var confDomain = flag.String("domain", "", "Specify a single domain.")

	var confScan = flag.Bool("scan", false, "Scan with given ListID, file or domain")
	var confAdd = flag.Bool("add", false, "Add given  file or domain to specified list")
	var confRemove = flag.Bool("remove", false, "Remove given file or domain from specified list")
	var confInactive = flag.Bool("inactive", false, "Set given file or domain to inactive")
	var confActive = flag.Bool("active", false, "Set given file or domain to active")

	var confOverwrite = flag.Bool("force", false, "Force conflicting entry overwrite")

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

	// read ForceOverwrite Flag
	forceOverwrite = *confOverwrite

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

	if !*confContinue {
		// parse Input settings
		test, err := parseSettings(*confList, *confFile, *confDomain, *confScan, *confAdd, *confRemove, *confInactive, *confActive)
		if err != nil {
			logger.Panic(err)
		}

		if !test {
			return
		}
		// create Scan if not continued
		currentScan, err = initializeScan(currentScan, usedManagers)
	} else {
		// continue last
		currentScan.ScanID = -1
		currentScan, err = continueScan(currentScan)

	}
	if err != nil {
		logger.Fatalf("Error occurred while initializing Scan: %v", err)
	}

	// start ui

	for _, manager := range usedManagers {
		apis.Start(hooks.ManagerMap[manager], currentScan.ScanID, *confContinue)
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
				currentScan.Done = true
				backend.UpdateScan(currentScan)
				break scan
			}
		}

	}

}

// reading DomainFile
func readLines(path *string) ([]string, error) {
	file, err := os.Open(*path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var line = strings.TrimSpace(scanner.Text())
		if (!strings.HasPrefix(line, "#")) && (line != "") {
			lines = append(lines, parseDomain(line))
		}
	}
	return lines, scanner.Err()
}

func parseDomain(domain string) string {
	if strings.Contains(domain, "//") {
		myURL, _ := url.Parse(domain)
		return myURL.Host
	}
	return domain
}
