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
	"log"
)

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

// Row of the domains Table
type DomainsRow struct {
	DomainID   int
	DomainName string
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

}
