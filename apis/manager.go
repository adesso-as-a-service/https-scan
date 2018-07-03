package apis

import (
	"fmt"
	"time"

	"../backend"
	"../hooks"

	// Initialize API-hooks
	_ "./crawler"
	_ "./observatory"
	_ "./securityheaders"
	_ "./ssllabs"
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
			// Add errorhandling
		}
	}
	domains, err := backend.GetScans(manager.GetTableName(), manager.ScanID, hooks.StatusPending)
	if err != nil {
		// Add errorhandling
	}
	return domains
}

// sendStatusMessage sends status message to the conroller
func sendStatusMessage(manager *hooks.Manager) {
	var mes = hooks.ScanStatus{
		CurrentScans:  manager.Status.GetCurrentScans(),
		ErrorScans:    manager.Status.GetErrorScans(),
		FinishedScans: manager.Status.GetFinishedScans(),
		TotalScans:    manager.Status.GetTotalScans(),
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
		panic(fmt.Errorf("Unknown Manager Tablename"))
		// Add errorhandling for unknown manager.table
	}

	domains = f(domains, internalChannel)
	return domains
}

// testFinished checks if all tests have been completed
func testFinished(manager *hooks.Manager, domains []hooks.DomainsReachable) bool {
	if manager.Status.GetCurrentScans() == 0 && manager.FirstScan {
		if len(domains) != 0 {
			if manager.FinishError >= finishErrorLimit {
				// Add errorhandling
				panic(fmt.Errorf("Exceeded finishErrorLimit: errorcount: %d limit: %d", manager.FinishError, finishErrorLimit))
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
		panic(fmt.Errorf("Unknown Manager Tablename"))
	}
	f(results)
}
