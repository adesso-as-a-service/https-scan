package main

import (
	"fmt"
	"sync/atomic"
	"time"
)

var statusTime = 4
var finishErrorLimit = 3

// Manager is a struct which combines values and functions needed by all scans individually
type Manager struct {
	maxRetries       int
	maxParallelScans int
	version          string
	table            string
	scanType         int
	outputChannel    chan scanStatusMessage
	LogLevel         int
	status           scanStatus
	finishError      int
	scanID           int
	errors           []internalMessage
	firstScan        bool
}

func (manager *Manager) getTableName() string {
	return manager.table + "V" + manager.version
}

// ScanStatus with atomic access
type scanStatus struct {
	currentScans  int32
	totalScans    int32
	errorScans    int32
	finishedScans int32
}

// ScanStatusMessage with atomic access
type scanStatusMessage struct {
	status *scanStatus
	sender string
}

// internalMessage
type internalMessage struct {
	domain     DomainsReachable
	results    interface{}
	retries    int
	statusCode int
}

const (
	internalFatalError = -1
	internalError      = 0
	internalSuccess    = 1
	internalNew        = 2
)

func (status *scanStatus) addCurrentScans(val int32) {
	atomic.AddInt32(&status.currentScans, val)
}

func (status *scanStatus) getCurrentScans() int32 {
	return atomic.LoadInt32(&status.currentScans)
}

func (status *scanStatus) addErrorScans(val int32) {
	atomic.AddInt32(&status.errorScans, val)
}

func (status *scanStatus) getErrorScans() int32 {
	return atomic.LoadInt32(&status.errorScans)
}

func (status *scanStatus) addFinishedScans(val int32) {
	atomic.AddInt32(&status.finishedScans, val)
}

func (status *scanStatus) getFinishedScans() int32 {
	return atomic.LoadInt32(&status.finishedScans)
}

func (status *scanStatus) setTotalScans(val int32) {
	atomic.StoreInt32(&status.totalScans, val)
}

func (status *scanStatus) getTotalScans() int32 {
	return atomic.LoadInt32(&status.totalScans)
}

//Datatypes
func (manager *Manager) run(scanID int, restart bool) {
	go manager.controll(scanID, restart)
}

func (manager *Manager) setUp() {
	// Do required SetUp
	switch manager.table {
	case "Crawler":

	case "SSLLabs":
		err := manager.labsRun()
		if err != nil {
			panic(err)
		}
	case "Observatory":

	case "SecurityHeaders":

	default:
		panic(fmt.Errorf("Unknown Manager Tablename"))
		// Add errorhandling for unknown manager.table
	}
}

// controll runs as a routine per manager handeling the scan
func (manager *Manager) controll(scanID int, restart bool) {
	manager.scanID = scanID
	domains := manager.receiveScans(restart)
	manager.status.setTotalScans(int32(len(domains)))
	updateTime := time.NewTicker(time.Second * time.Duration(statusTime)).C
	internalChannel := make(chan internalMessage)
	manager.setUp()
	for {
		select {
		case <-updateTime:
			manager.sendStatusMessage()
		case res := <-internalChannel:
			manager.handleResults(res)
		default:
			domains = manager.handleScans(domains, internalChannel)
			if manager.testFinished(domains) {
				// needs to send goodbye
				manager.outputChannel <- scanStatusMessage{nil, manager.table}
				return
			}
		}
	}
}

// receiveScans extracts the scans saved in the table
func (manager *Manager) receiveScans(restart bool) []DomainsReachable {
	if !restart {
		err := prepareScanData(manager.getTableName(), manager.scanID, manager.scanType)
		if err != nil {
			// Add errorhandling
		}
	}
	domains, err := getScans(manager.getTableName(), manager.scanID, statusPending)
	if err != nil {
		// Add errorhandling
	}
	return domains
}

// sendStatusMessage sends status message to the conroller
func (manager *Manager) sendStatusMessage() {
	var mes = scanStatus{
		currentScans:  manager.status.getCurrentScans(),
		errorScans:    manager.status.getErrorScans(),
		finishedScans: manager.status.getFinishedScans(),
		totalScans:    manager.status.getTotalScans(),
	}
	manager.outputChannel <- scanStatusMessage{&mes, manager.table}
}

//handleScans checks if new scans should be started and starts them if needed
func (manager *Manager) handleScans(domains []DomainsReachable, internalChannel chan internalMessage) []DomainsReachable {
	if int(manager.status.getCurrentScans()) >= manager.maxParallelScans {
		return domains
	}
	switch manager.table {
	case "Crawler":
		domains = manager.crawlerHandleScan(domains, internalChannel)

	case "SSLLabs":
		domains = manager.labsHandleScan(domains, internalChannel)
	case "Observatory":
		domains = manager.obsHandleScan(domains, internalChannel)
	case "SecurityHeaders":
		domains = manager.sechHandleScan(domains, internalChannel)
	default:
		panic(fmt.Errorf("Unknown Manager Tablename"))
		// Add errorhandling for unknown manager.table
	}
	return domains
}

// testFinished checks if all tests have been completed
func (manager *Manager) testFinished(domains []DomainsReachable) bool {
	if manager.status.getCurrentScans() == 0 && manager.firstScan {
		if len(domains) != 0 {
			if manager.finishError >= finishErrorLimit {
				// Add errorhandling
				panic(fmt.Errorf("Exceeded finishErrorLimit: errorcount: %d limit: %d", manager.finishError, finishErrorLimit))
			}
			manager.finishError++
			return false
		}
		return true
	}
	return false
}

// handleResults saves finished scans
func (manager *Manager) handleResults(results internalMessage) {
	switch manager.table {
	case "Crawler":
		manager.crawlerHandleResults(results)
	case "SSLLabs":
		manager.labsHandleResults(results)
	case "Observatory":
		manager.obsHandleResults(results)
	case "SecurityHeaders":
		manager.sechHandleResults(results)
	default:
		panic(fmt.Errorf("Unknown Manager Tablename"))
	}
}

func truncate(str string, trLen int) string {
	if len(str) > trLen {
		return str[:trLen]
	}
	return str
}
