package apis

import (
	"github.com/sirupsen/logrus"
	"time"

	"../backend"
	"../hooks"

	// Initialize API-hooks
	_ "./crawler"
	_ "./observatory"
	_ "./observatory_tls"
	_ "./securityheaders"
	_ "./ssllabs"
	// Example API
	// _ "./example"
)

var StatusTime = 4
var finishErrorLimit = 3

var Logger *logrus.Logger

//Datatypes
func Start(manager *hooks.Manager, scanID int, restart bool) {
	go control(manager, scanID, restart)
}

func setUp(manager *hooks.Manager) {
	// Do required SetUp
	for _, setUpFunction := range hooks.ManagerSetUp {
		setUpFunction()
	}
}

// control runs as a routine per manager handling the scan
func control(manager *hooks.Manager, scanID int, restart bool) {
	manager.ScanID = scanID
	domains := receiveScans(manager, restart)

	hooks.Logger.Infof("Found %d domains to scan", len(domains))

	// if no domains to scan, just finished
	if len(domains) == 0 {
		manager.FirstScan = true
	}
	manager.Status.SetTotalScans(int32(len(domains)))
	updateTime := time.NewTicker(time.Second * time.Duration(StatusTime)).C
	internalChannel := make(chan hooks.InternalMessage)
	setUp(manager)
	for {
		select {
		case <-updateTime:
			sendStatusMessage(manager)
		case res := <-internalChannel:
			handleResults(manager, res)
		default:
			domains = handleScans(manager, domains, internalChannel)
			if testFinished(manager, domains) {
				// needs to send goodbye
				manager.Logger.Info("Scan complete, shutting down")
				sendStatusMessage(manager)
				manager.OutputChannel <- hooks.ScanStatusMessage{
					Status: nil,
					Sender: manager.Table,
				}
				return
			}
		}
	}
}

// receiveScans extracts the scans saved in the table
func receiveScans(manager *hooks.Manager, restart bool) []hooks.DomainsReachable {
	if !restart {
		err := backend.PrepareScanData(manager.GetTableName(), manager.ScanID, manager.ScanType)
		if err != nil {
			manager.Logger.WithFields(logrus.Fields{"error": err}).Panic("Preparing Scan Data failed")
		}
	}
	domains, err := backend.GetScans(manager.GetTableName(), manager.ScanID, hooks.StatusPending)
	if err != nil {
		manager.Logger.WithFields(logrus.Fields{"error": err}).Panic("Reading Scans from Database failed")
	}
	return domains
}

// sendStatusMessage sends status message to the controller
func sendStatusMessage(manager *hooks.Manager) {
	manager.Logger.Infof("Running: %5d    Retrying: %5d    Failed:%5d    Remaining: %5d    ",
		manager.Status.GetCurrentScans(),
		manager.Status.GetErrorScans(),
		manager.Status.GetFatalErrorScans(),
		manager.Status.GetTotalScans()-manager.Status.GetFinishedScans())

	var mes = hooks.ScanStatus{
		CurrentScans:    manager.Status.GetCurrentScans(),
		ErrorScans:      manager.Status.GetErrorScans(),
		FinishedScans:   manager.Status.GetFinishedScans(),
		TotalScans:      manager.Status.GetTotalScans(),
		FatalErrorScans: manager.Status.GetFatalErrorScans(),
	}
	manager.OutputChannel <- hooks.ScanStatusMessage{
		Status: &mes,
		Sender: manager.Table,
	}
}

//handleScans checks if new scans should be started and starts them if needed
func handleScans(manager *hooks.Manager, domains []hooks.DomainsReachable, internalChannel chan hooks.InternalMessage) []hooks.DomainsReachable {
	if int(manager.Status.GetCurrentScans()) >= manager.MaxParallelScans {
		return domains
	}
	f := hooks.ManagerHandleScan[manager.Table]
	if f == nil {
		manager.Logger.WithFields(logrus.Fields{
			"tableName": manager.Table,
		}).Panic("Unknown manager table name")
	}

	domains = f(domains, internalChannel)
	return domains
}

// testFinished checks if all tests have been completed
func testFinished(manager *hooks.Manager, domains []hooks.DomainsReachable) bool {
	if manager.Status.GetRemainingScans() == 0 && manager.FirstScan {
		if len(domains) != 0 && len(manager.Errors) != 0 {
			if manager.FinishError >= finishErrorLimit {
				manager.Logger.WithFields(logrus.Fields{
					"errorcount": manager.FinishError,
					"limit":      finishErrorLimit,
				}).Panic("Exceeded finishErrorLimit")
			}
			manager.FinishError++
			return false
		}
		return true
	}
	return false
}

// handleResults saves finished scans
func handleResults(manager *hooks.Manager, results hooks.InternalMessage) {

	handleResultsFunction := hooks.ManagerHandleResults[manager.Table]
	if handleResultsFunction == nil {
		manager.Logger.WithFields(logrus.Fields{"tableName": manager.Table}).Panic("Unknown manager table name")
	}
	if results.Retries != 0 {
		manager.Status.AddErrorScans(-1)
	}
	if results.StatusCode == hooks.InternalError {
		if results.Retries >= manager.MaxRetries {
			results.StatusCode = hooks.InternalFatalError
		} else {
			results.Retries++
			manager.Errors = append(manager.Errors, results)
			manager.Status.AddErrorScans(1)
			manager.Status.AddCurrentScans(-1)
			manager.Logger.Debugf("Retrying %v for the %d. times", results.Domain.DomainName, results.Retries)
			return
		}
	}
	handleResultsFunction(results)
}
