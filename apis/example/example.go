package example

import (
	"../../backend"
	"../../hooks"
	"encoding/json"
	"flag"
	"github.com/fatih/structs"
)

/* ------------------------------------------------------------
			             !!! TODO !!!

	Add struct that contains the fields stored in the Database.
	It has to always contain the 'ScanStatus'-field

------------------------------------------------------------ */

// TableRow represents the scan results for the crawler table
type TableRow struct {
	// TableRows
	ScanStatus int
}

// maxRedirects sets the maximum number of Redirects to be followed
var maxRedirects int

var maxScans int

var used *bool

var maxRetries *int

/* ------------------------------------------------------------
			             !!! TODO !!!

	Name the manager and set the version of the scanner.
	1.0 --> 10

	Also add additional config fields to the 'Config'-struct if
	needed and add default values for them to 'currentConfig'

------------------------------------------------------------ */

// exampleVersion
var version = "10"

// exampleManager
var manager = hooks.Manager{
	MaxRetries:       3,        //Max Retries
	MaxParallelScans: maxScans, //Max parallel Scans
	Version:          version,
	Table:            "EXAMPLE",                 //Table name
	ScanType:         hooks.ScanBoth,            // Scan HTTP or HTTPS
	OutputChannel:    nil,                       //output channel
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
	LoggingTag:       "example",
}

// Config contains the configurable Values for this scan
type Config struct {
	Retries       int
	ScanType      int
	ParallelScans int
}

// defaultConfig
var currentConfig = Config{
	Retries:       3,
	ScanType:      hooks.ScanBoth,
	ParallelScans: 10,
	LogLevel:      "info",
}

/* ------------------------------------------------------------
			             !!! TODO !!!

	'handleScan' starts a new assessment if there is room for
	another parallel assessment.

	1. If needed add a custom assessment start conditions.
	   Normally an assessment is started when the number of
	   current scans is lower than the number of allowed
	   parallel scans.

------------------------------------------------------------ */

func handleScan(domains []hooks.DomainsReachable, internalChannel chan hooks.InternalMessage) []hooks.DomainsReachable {
	for (len(manager.Errors) > 0 || len(domains) > 0) && int(manager.Status.GetCurrentScans()) < manager.MaxParallelScans {
		manager.FirstScan = true
		var scanMsg hooks.InternalMessage
		var retDom = domains
		var scan hooks.DomainsReachable
		// pop fist domain
		if manager.CheckDoError() && len(manager.Errors) != 0 {
			scanMsg, manager.Errors = manager.Errors[0], manager.Errors[1:]
			manager.Logger.Tracef("Retrying failed assessment next: %v", scanMsg.Domain.DomainName)
		} else if len(domains) != 0 {
			scan, retDom = domains[0], domains[1:]
			scanMsg = hooks.InternalMessage{
				Domain:     scan,
				Results:    nil,
				Retries:    0,
				StatusCode: hooks.InternalNew,
			}
			manager.Logger.Tracef("Trying new assessment next: %v", scanMsg.Domain.DomainName)
		} else {
			manager.Logger.Tracef("No new assessment started")
			return domains
		}
		manager.Logger.Debugf("Started assessment for %v", scanMsg.Domain.DomainName)
		go assessment(scanMsg, internalChannel)
		manager.Status.AddCurrentScans(1)
		return retDom
	}
	manager.Logger.Tracef("no new Assessment started")
	return domains
}

/* ------------------------------------------------------------
			             !!! TODO !!!

	'handleResults' saves the results of an assessment in the
	database.

	1. If the results returned from the assessment have to
	   handled specially, add the code here.

------------------------------------------------------------ */

func handleResults(result hooks.InternalMessage) {
	res, ok := result.Results.(TableRow)
	manager.Status.AddCurrentScans(-1)

	if !ok {
		manager.Logger.Errorf("Couldn't assert type of result for  %v", result.Domain.DomainName)
		res = TableRow{}
		result.StatusCode = hooks.InternalFatalError
	}

	switch result.StatusCode {
	case hooks.InternalFatalError:
		res.ScanStatus = hooks.StatusError
		manager.Status.AddFatalErrorScans(1)
		manager.Logger.Infof("Assessment of %v failed ultimately", result.Domain.DomainName)
	case hooks.InternalSuccess:
		res.ScanStatus = hooks.StatusDone
		manager.Logger.Debugf("Assessment of %v was successful", result.Domain.DomainName)
		manager.Status.AddFinishedScans(1)
	}
	where := hooks.ScanWhereCond{
		DomainID:    result.Domain.DomainID,
		ScanID:      manager.ScanID,
		TestWithSSL: result.Domain.TestWithSSL}
	err := backend.SaveResults(manager.GetTableName(), structs.New(where), structs.New(res))
	if err != nil {
		manager.Logger.Errorf("Couldn't save results for %v: %v", result.Domain.DomainName, err)
		return
	}
	manager.Logger.Debugf("Results for %v saved", result.Domain.DomainName)

}

/* ------------------------------------------------------------
			             !!! TODO !!!

	'assessment' contains the assessment procedureand returns
	the results on the 'internalChannel'. Add the assessment-
	logic here

------------------------------------------------------------ */

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {
	// Changes if test is done via SSL
	if scan.Domain.TestWithSSL {

	} else {

	}

	// Add your assessment logic
	//		row = yourAssessment(...)

	//Handle error
	if err != nil {
		manager.Logger.Errorf("Assessment failed for %v: %v", scan.Domain.DomainName, err)
		scan.Results = row
		scan.StatusCode = hooks.InternalError
		internalChannel <- scan
		return
	}

	//return results
	scan.Results = row
	scan.StatusCode = hooks.InternalSuccess
	internalChannel <- scan
}

/* ------------------------------------------------------------
			             !!! TODO !!!

	'flagSetUp' allows you to add custom commandline flags for
	your api. Here the flag to disable it in scans is already
	added.

------------------------------------------------------------ */

func flagSetUp() {
	used = flag.Bool("no-EXAMPLE", false, "Don't use the EXAMPLE crawler")
}

/* ------------------------------------------------------------
			             !!! TODO !!!

	'configureSetUp' and 'parseConfig' set the configuration
	read from Commandline or defaultConfig. Add your logic for
	these here.

------------------------------------------------------------ */

func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage, config interface{}) bool {
	currentScan.Crawler = !*used
	currentScan.CrawlerVersion = manager.Version
	if !*used {
		if manager.MaxParallelScans != 0 {
			parseConfig(config)
			manager.OutputChannel = channel
			return true
		}
	}
	return false
}

// reads Config from interfaceFormat to Config and saves Results
func parseConfig(config interface{}) {
	jsonString, err := json.Marshal(config)
	if err != nil {
		manager.Logger.Errorf("Failed parsing config to interface: %v", err)
	}
	err = json.Unmarshal(jsonString, &currentConfig)
	if err != nil {
		manager.Logger.Errorf("Failed parsing json to struct: %v", err)
	}
	manager.MaxRetries = currentConfig.Retries
	manager.ScanType = currentConfig.ScanType
	maxScans = currentConfig.ParallelScans
}

func continueScan(scan hooks.ScanRow) bool {
	return manager.Version == scan.CrawlerVersion
}

/* ------------------------------------------------------------
			             !!! TODO !!!

	In 'setUp' you can add logic that needs to be executed
	before any assessments start

------------------------------------------------------------ */

func setUp() {
	var logger = apis.Logger
	manager.Logger = logger.WithField("hook", manager.LoggingTag)
}

func init() {
	hooks.ManagerMap[manager.Table] = &manager

	hooks.FlagSetUp[manager.Table] = flagSetUp

	hooks.ConfigureSetUp[manager.Table] = configureSetUp

	hooks.ContinueScan[manager.Table] = continueScan

	hooks.ManagerSetUp[manager.Table] = setUp

	hooks.ManagerHandleScan[manager.Table] = handleScan

	hooks.ManagerHandleResults[manager.Table] = handleResults

	hooks.ManagerParseConfig[manager.Table] = parseConfig

}
