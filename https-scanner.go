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
	"encoding/json"
	"flag"
	"fmt"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"time"

	"./apis"
	"./backend"
	"./hooks"
)

var Logger *logrus.Entry

var forceOverwrite bool
var configuration map[string]interface{}

func getTablenames(usedManagers []string) []string {
	var result []string
	for _, manager := range usedManagers {
		man := hooks.ManagerMap[manager]
		result = append(result, man.GetTableName())
	}
	return result
}

// initializeScan starts the scan specified in the hooks.ScanRow parameter
func initializeScan(scan hooks.ScanRow, usedTables []string) (hooks.ScanRow, error) {
	var err error
	scan, err = backend.InsertNewScan(scan)
	if err != nil {
		return scan, err
	}
	Logger.Infof("Starting Scan with ScanID %d", scan.ScanID)

	domains, err := backend.GetDomains()
	if err != nil {
		return scan, err
	}
	if len(domains) == 0 {
		backend.UpdateScan(scan)
		Logger.Fatal("There are no domains to scan!")
	}
	scanData, scan, err := runSSLTest(domains, scan)
	if err != nil {
		return scan, err
	}
	if len(scanData) == 0 {
		backend.UpdateScan(scan)
		Logger.Fatal("There are no domains left to scan after a reachability test!")
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

	// configuring Apis and set used managers
	for tableName, f := range hooks.ManagerParseConfig {
		f(configuration[tableName])
	}

	for tableName, f := range hooks.ContinueScan {
		if !f(scan) {
			broken = append(broken, tableName)
		}
	}

	if len(broken) != 0 {
		err = fmt.Errorf("The version for the following Scans have changed in the meantime: %s! Please start a new Scan", strings.Join(broken, ", "))
	}
	Logger.Infof("Continuing Scan with ScanID %d", scan.ScanID)
	return scan, err
}

// conflictAdd handles adding conflicting entries to a ListID
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
			fmt.Printf("Conflicting Entries:\n\tOld: Domain: %s\tListID: %s\tActive: %v\n\tNew: Domain: %s\tListID: %s\tActive: %v\n",
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

// parseSettings parses the command line flags and performs the corresponding tasks
func parseSettings(list string, file string, domain string, scan bool, add bool, remove bool, inactive bool, active bool, project string) (bool, error) {
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

	if len(domains) == 0 && list == "" && project == "" {
		return false, fmt.Errorf("No domains, ListID or project have been specified")
	} else if project != "" {
		if scan {
			// set up scan and return true
			err := backend.ScanDomainsWithProjectID(project)
			return true, err
		} else {
			return false, fmt.Errorf("Projects only scannable")
		}

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

func setUpLogging(confVerbosity *string, confLogFormat *string, confLogReportCaller *bool) {
	var loglevel, parseLevelError = logrus.ParseLevel(*confVerbosity)
	if parseLevelError != nil {
		loglevel = logrus.TraceLevel
	}

	var loggerConfiguration = logrus.New()
	loggerConfiguration.SetLevel(loglevel)
	loggerConfiguration.SetReportCaller(*confLogReportCaller)

	// Setup logging to stdout (text or json format)
	switch *confLogFormat {
	case "json":
		loggerConfiguration.SetFormatter(&logrus.JSONFormatter{})
	default:
		loggerConfiguration.SetFormatter(&logrus.TextFormatter{
			DisableColors:          false,
			PadLevelText:           true,
			DisableLevelTruncation: true,
		})
	}

	// Setup logging to file (always json format)
	if _, err := os.Stat("log"); os.IsNotExist(err) {
		if err != nil {
			loggerConfiguration.WithFields(logrus.Fields{"error": err}).Errorf("Failed retrieving FileInfo for file logging")
		} else {
			err = os.Mkdir("log", 0700)
			if err != nil {
				loggerConfiguration.WithFields(logrus.Fields{"error": err}).Errorf("Error while creating log directory")
			}
		}
	}
	file, err := os.Create("log/" + time.Now().Format("2006_01_02_150405") + ".log")
	if err != nil {
		loggerConfiguration.WithFields(logrus.Fields{"error": err}).Errorf("Failed to set up file logging")
	} else {
		loggerConfiguration.Hooks.Add(lfshook.NewHook(
			file,
			&logrus.JSONFormatter{},
		))
	}

	// hook attribute should always be set for log parsers (HIDS, CLC, ...)
	Logger = loggerConfiguration.WithFields(logrus.Fields{"hook": nil})

	hooks.Logger = Logger
	backend.Logger = Logger

	Logger.WithFields(logrus.Fields{"chosen_level": loglevel, "error": parseLevelError}).Info("Logging has been initialized")
}

func main() {
	// Read input arguments
	var confVerbosity = flag.String("verbosity", "info", "Configure log verbosity: panic, fatal, error, warn/warning, info, debug and trace")
	var confLogFormat = flag.String("log_format", "text", "Configure log format: text or json")
	var confLogReportCaller = flag.Bool("log_report_caller", false, "Add calling method as logging field (should be used for debugging only)")

	var confContinue = flag.Bool("continue", false, "Continue the last scan")

	var confList = flag.String("list", "", "Specify a ListID")
	var confFile = flag.String("file", "", "Specify a file containing multiple domains (separated by linebreak)")
	var confDomain = flag.String("domain", "", "Specify a single domain")
	var confProject = flag.String("project", "", "Specify a project id")

	var confScan = flag.Bool("scan", false, "Scan the given domains")
	var confAdd = flag.Bool("add", false, "Add the given domains to the specified ListID")
	var confRemove = flag.Bool("remove", false, "Remove the given domains from the specified ListID")
	var confInactive = flag.Bool("inactive", false, "Set the given domains to inactive (only active domains are scanned)")
	var confActive = flag.Bool("active", false, "Set the given domains to active (only active domains are scanned)")

	var confOverwrite = flag.Bool("force", false, "Force overwrite, if there are conflicting adds")

	var confConfig = flag.String("config", "", "Configuration file for the scanners")

	loc, err := time.LoadLocation("UTC")
	if err != nil {
	}
	time.Local = loc // -> this is setting the global timezone
	
	// setUp Input Arguments for apis
	for _, hookSetUpFunction := range hooks.FlagSetUp {
		hookSetUpFunction()
	}

	flag.Parse()

	// Initialize logging
	setUpLogging(confVerbosity, confLogFormat, confLogReportCaller)

	// Variables
	var err error
	// names of Managers used
	var usedManagers []string
	var currentScan hooks.ScanRow

	// read ForceOverwrite Flag
	forceOverwrite = *confOverwrite

	// create output channel
	outputChannel := make(chan hooks.ScanStatusMessage)
	timeout := make(map[string]time.Time)
	finished := make(map[string]bool)

	// ToDo: still used?
	if *confConfig != "" && !*confContinue {
		configuration, err = readConfigFile(*confConfig)
		if err != nil {
			Logger.WithFields(logrus.Fields{
				"config": *confConfig,
				"error":  err,
			}).Panic("Failed reading configuration-file")
		}
		configString, err := json.Marshal(configuration)
		if err != nil {
			Logger.WithFields(logrus.Fields{"error": err}).Panic("Failed reading configuration-file")
		}
		currentScan.Config.String = string(configString)
		currentScan.Config.Valid = true
	}
	// configuring Apis and set used managers
	for tableName, hookConfigureSetUpFunction := range hooks.ConfigureSetUp {
		if hookConfigureSetUpFunction(&currentScan, outputChannel, configuration[tableName]) {
			usedManagers = append(usedManagers, tableName)
		}
	}

	config, err := backend.ReadSQLConfig("sql_config.json")
	if err != nil {
		Logger.Fatalf("Error occurred while reading the config-file 'sql_config.json': %v", err)
	}
	Logger.Info("Reading SQL Config completed")

	// Opening Database
	err = backend.OpenDatabase(config)
	if err != nil {

		Logger.Fatalf("Error occurred while opening the database: %v", err)
	}

	if !*confContinue {
		// parse Input settings
		test, err := parseSettings(*confList, *confFile, *confDomain, *confScan, *confAdd, *confRemove, *confInactive, *confActive, *confProject)
		if err != nil {
			Logger.Fatal(err)
		}

		if !test {
			return
		}
		// create Scan if not continued
		currentScan, err = initializeScan(currentScan, usedManagers)
		if err != nil {
			Logger.Fatalf("Error during initializeScan: %v", err)
		}
	} else {
		// continue last
		currentScan.ScanID = -1
		currentScan, err = continueScan(currentScan)

	}
	if err != nil {
		Logger.Fatalf("Error occurred while initializing Scan: %v", err)
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
				Logger.Tracef("Received status message from '%v'", msg.Sender)
				timeout[msg.Sender] = time.Now()
			} else {
				Logger.Debugf("Received 'finished' message from %v", msg.Sender)
				finished[msg.Sender] = true
			}
		case <-updateTime:
			allDone := true
			for _, manager := range usedManagers {
				allDone = allDone && finished[manager]
				if !finished[manager] && time.Since(timeout[manager]) > time.Duration(5*apis.StatusTime)*time.Second {
					Logger.Fatalf("Manager %s has been unreachable for %d seconds", manager, 5*apis.StatusTime)
				}

			}
			if allDone {
				Logger.Infof("Scan with ScanID %d is done", currentScan.ScanID)
				currentScan.Done = true
				err := backend.UpdateScan(currentScan)

				if err != nil {
					Logger.WithFields(logrus.Fields{
						"error": err,
						"data":  currentScan,
					}).Error("Database UPDATE failed")
				}

				err = backend.RemoveIgnored(currentScan)
				if err != nil {
					Logger.WithFields(logrus.Fields{
						"error": err,
						"data":  currentScan,
					}).Error("Cannot delete ignored results")
				} else {
					Logger.Info("Ignored results have been deleted")
				}

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

// Read Config from File
func readConfigFile(file string) (map[string]interface{}, error) {
	var result map[string]interface{}
	jsonString, err := ioutil.ReadFile(file)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(jsonString, &result)

	return result, err

}
