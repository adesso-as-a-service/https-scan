package apis

import (
	"fmt"
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

//Datatypes
func Start(manager *hooks.Manager, scanID int, restart bool) {
	go controll(manager, scanID, restart)
}

func setUp(manager *hooks.Manager) {
	// Do required SetUp
	for _, f := range hooks.ManagerSetUp {
		f()
	}
}

// controll runs as a routine per manager handeling the scan
func controll(manager *hooks.Manager, scanID int, restart bool) {
	manager.ScanID = scanID
	domains := receiveScans(manager, restart)
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
				hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Scan complete, shutting down"), manager.LogLevel, hooks.LogInfo)
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
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Prepareing Scan Data failed: %v", err), manager.LogLevel, hooks.LogCritical)
		}
	}
	domains, err := backend.GetScans(manager.GetTableName(), manager.ScanID, hooks.StatusPending)
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Reading Scans from Database failed: %v", err), manager.LogLevel, hooks.LogCritical)
	}
	return domains
}

// sendStatusMessage sends status message to the conroller
func sendStatusMessage(manager *hooks.Manager) {
	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Running: %5d    Retrying: %5d    Failed:%5d    Remaining: %5d    ", manager.Status.GetCurrentScans(), manager.Status.GetErrorScans(), manager.Status.GetFatalErrorScans(), manager.Status.GetTotalScans()-manager.Status.GetFinishedScans()), manager.LogLevel, hooks.LogInfo)
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
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Unknown manager table name %v", manager.Table), manager.LogLevel, hooks.LogCritical)
	}

	domains = f(domains, internalChannel)
	return domains
}

// testFinished checks if all tests have been completed
func testFinished(manager *hooks.Manager, domains []hooks.DomainsReachable) bool {
	if manager.Status.GetRemainingScans() == 0 && manager.FirstScan {
		if len(domains) != 0 && len(manager.Errors) != 0 {
			if manager.FinishError >= finishErrorLimit {
				hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Exceeded finishErrorLimit: errorcount: %d limit: %d", manager.FinishError, finishErrorLimit), manager.LogLevel, hooks.LogCritical)
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

	f := hooks.ManagerHandleResults[manager.Table]
	if f == nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Unknown manager table name %v", manager.Table), manager.LogLevel, hooks.LogCritical)
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
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Retrying %v for the %d. times", results.Domain.DomainName, results.Retries), manager.LogLevel, hooks.LogDebug)
			return
		}
	}
	f(results)
}
