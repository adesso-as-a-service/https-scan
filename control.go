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
	"os"
	"strings"
	"time"
)

// SQLConfiguration collects the Data needed for Connecting to an SQL-Database
type SQLConfiguration struct {
	SQLServer     string
	SQLUserID     string
	SQLPassword   string
	SQLDatabase   string
	SQLEncryption string
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
	scanOnlySSL  = 1
	scanOnlyHTTP = 2
	scanBoth     = 3
	//scanOnePreferSSL  = 4
	//scanOnePreferHTTP = 5
)

const (
	statusError   = -1
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

func main() {
	startTime := time.Now()
	var conf_api = flag.String("api", "BUILTIN", "API entry point, for example https://www.example.com/api/")
	var conf_grade = flag.Bool("grade", false, "Output only the hostname: grade")
	var conf_hostcheck = flag.Bool("hostcheck", false, "If true, host resolution failure will result in a fatal error.")
	var conf_hostfile = flag.String("hostfile", "", "File containing hosts to scan (one per line)")
	var conf_ignore_mismatch = flag.Bool("ignore-mismatch", false, "If true, certificate hostname mismatch does not stop assessment.")
	var conf_insecure = flag.Bool("insecure", false, "Skip certificate validation. For use in development only. Do not use.")
	var conf_json_flat = flag.Bool("json-flat", false, "Output results in flattened JSON format")
	var conf_quiet = flag.Bool("quiet", false, "Disable status messages (logging)")
	var conf_usecache = flag.Bool("usecache", false, "If true, accept cached results (if available), else force live scan.")
	var conf_maxage = flag.Int("maxage", 0, "Maximum acceptable age of cached results, in hours. A zero value is ignored.")
	var conf_verbosity = flag.String("verbosity", "info", "Configure log verbosity: error, notice, info, debug, or trace.")
	var conf_version = flag.Bool("version", false, "Print version and API location information and exit")

	//Added Flags
	var conf_securityheaders = flag.Bool("no-securityheaders", false, "Don't include a scan for security headers")
	var conf_sql_retries = flag.Int("sql-retries", 3, "Number of retries if the SQL-connection fails")
	var conf_observatory = flag.Bool("no-observatory", false, "Don't include a scan using the mozilla observatory API")
	var conf_ssllabs = flag.Bool("no-ssllabs", false, "Don't use SSLlabs-Scan")
	var conf_ssltest = flag.Bool("no-ssltest", false, "Don't test hosts before starting Scan")
	var conf_sql = flag.Bool("no-sql", false, "Don't write results into the database")
	var conf_sslTries = flag.Int("sslTest-retries", 1, "Number of retries if the sslTest fails")
	var conf_labsTries = flag.Int("labs-retries", 0, "Number of retries if the sslLabs-Scan fails")
	var conf_obsTries = flag.Int("obs-retries", 1, "Number of retries if the Observatory-Scan fails")
	var conf_secHTries = flag.Int("secH-retries", 2, "Number of retries if the Securityheader-Scan fails")
	var conf_maxAssessments = flag.Float64("maxFactor", 1.0, "Relative Auslastung von MaxAssessments")
	var conf_continue = flag.Bool("continue", false, "continue Scan after error")

	flag.Parse()

	// Setup according to flags

	// Setting max retries for all managers
	sslTries = *conf_sslTries + 1
	obsTries = *conf_obsTries + 1
	labsTries = *conf_labsTries + 1
	secHTries = *conf_secHTries + 1

	if sslTries < 1 {
		sslTries = 1
	}

	if labsTries < 1 {
		labsTries = 1
	}
	if obsTries < 1 {
		obsTries = 1
	}

	if secHTries < 1 {
		secHTries = 1
	}

	if *conf_maxAssessments > 1.0 {
		faktor = 1.0
	} else {
		faktor = *conf_maxAssessments
	}

	globalSQLRetries = *conf_sql_retries

	// sql needs to know if observatory is used
	if !*conf_observatory {
		globalObservatory = true
	}

	if *conf_version {
		fmt.Println(USER_AGENT)
		fmt.Println("API location: " + apiLocation)
		return
	}

	logLevel = parseLogLevel(strings.ToLower(*conf_verbosity))

	globalIgnoreMismatch = *conf_ignore_mismatch

	if *conf_quiet {
		logLevel = LOG_NONE
	}

	// We prefer cached results
	if *conf_usecache {
		globalFromCache = true
		globalStartNew = false
	}

	if *conf_maxage != 0 {
		globalMaxAge = *conf_maxage
	}

	// Verify that the API entry point is a URL.
	if *conf_api != "BUILTIN" {
		apiLocation = *conf_api
	}

	if validateURL(apiLocation) == false {
		log.Fatalf("[ERROR] Invalid API URL: %v", apiLocation)
	}

	var hostnames []string

	if *conf_hostfile != "" {
		// Open file, and read it
		var err error
		hostnames, err = readLines(conf_hostfile)
		if err != nil {
			log.Fatalf("[ERROR] Reading from specified hostfile failed: %v", err)
		}
		if *conf_continue {
			cFName := "finished"
			finishedHostnames, err := readLines(&cFName)
			if err != nil {
				log.Fatalf("[ERROR] Reading from specified hostfile failed: %v", err)
			}
			hostnames = cleanList(hostnames, finishedHostnames)
		}

	} else {
		// Read hostnames from the rest of the args
		hostnames = flag.Args()
	}
	var err error
	if *conf_continue {
		continueFile, err = os.OpenFile("finished", os.O_APPEND|os.O_WRONLY, 0644)

		if err != nil {
			log.Fatalf("[FATAL] Could not create continue File %v: %v", "finished", err.Error())
		}
		defer continueFile.Close()
	} else {
		os.Remove("finished")
		continueFile, err = os.OpenFile("finished", os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("[FATAL] Could not create continue File %v: %v", "finished", err.Error())
		}
		defer continueFile.Close()
	}

	if *conf_hostcheck {
		// Validate all hostnames before we attempt to test them. At least
		// one hostname is required.
		for _, host := range hostnames {
			if validateHostname(host) == false {
				log.Fatalf("[ERROR] Invalid hostname: %v", host)
			}
		}
	}

	if *conf_insecure {
		globalInsecure = *conf_insecure
	}

	if *conf_ssllabs && *conf_ssltest && *conf_observatory && *conf_securityheaders {
		log.Fatal("[ERROR] At least one can has to be run!")
	}

	// set the steps to be used
	var useing = map[string]bool{"labs": !*conf_ssllabs, "obs": !*conf_observatory, "secH": !*conf_securityheaders, "sql": !*conf_sql, "ssl": !*conf_ssltest}

	// create files and directories for logging output and results
	err = os.Mkdir("log", 0700)
	if err != nil && os.IsNotExist(err) {
		log.Fatalf("[FATAL] Could not create loggingFolder log: %v", err.Error())
	}

	err = os.Mkdir("results", 0700)
	if err != nil && os.IsNotExist(err) {
		log.Fatalf("[FATAL] Could not create resultFolder res: %v", err.Error())
	}

	// files are named after this date-time schema
	FileName := time.Now().Format("2006_01_02_150405")

	logFile, err = os.Create("log/" + FileName + ".log")

	if err != nil {
		log.Fatalf("[FATAL] Could not create logging File %v: %v", "log/"+FileName+".log", err.Error())
	}
	defer logFile.Close()

	resFile, err := os.Create("results/" + FileName + ".result")

	if err != nil {
		log.Fatalf("[FATAL] Could not create resultFile %v: %v", "results/"+FileName+".result", err.Error())
	}
	defer resFile.Close()

	// create HostProvider containing the host that need to be analyzed
	hp := newHostProvider(hostnames)

	// start analysis by starting control

	manager := NewMasterManager(hp, useing, continueFile)

}
