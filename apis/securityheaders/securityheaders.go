package securityheaders

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"../../backend"
	"../../hooks"
	"github.com/fatih/structs"
	"golang.org/x/net/html"
)

// CrawlerMaxRedirects sets the maximum number of Redirects to be followed
var maxScans = 5

// crawlerVersion
var version = "10"

var used *bool

var maxRetries *int

var logger *log.Logger

var manager = hooks.Manager{
	MaxRetries:       3,        //Max Retries
	MaxParallelScans: maxScans, //Max parallel Scans
	Version:          version,
	Table:            "Securityheaders",         //Table name
	ScanType:         hooks.ScanBoth,            // Scan HTTP or HTTPS
	OutputChannel:    nil,                       //output channel
	LogLevel:         hooks.LogNotice,           //loglevel
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
}

// CrawlerConfig
type Config struct {
	Retries        int
	ScanType       int
	ParallelScans  int
	LogLevel       string
	Hidden         string
	FollowRedirect string
	APILocation    string
}

// defaultConfig
var currentConfig = Config{
	Retries:        3,
	ScanType:       hooks.ScanBoth,
	APILocation:    "https://securityheaders.io/?q=",
	ParallelScans:  10,
	LogLevel:       "info",
	Hidden:         "on",
	FollowRedirect: "off",
}

// TableRow is the object used for unmarshaling the results by the API
type TableRow struct {
	Grade                   string
	XFrameOptions           string
	StrictTransportSecurity string
	XContentTypeOptions     string
	XXSSProtection          string
	ContentSecurityPolicy   string
	ReferrerPolicy          string
	ScanStatus              int
}

// parseResponse extracts the results of the securityheaders-scan out of the request response
func parseResponse(r io.Reader) *TableRow {
	z := html.NewTokenizer(r)
	var secH TableRow
	isRaw := false
	isMissing := false

	for {
		tt := z.Next()
		switch {
		case tt == html.ErrorToken:
			return &secH
		case tt == html.EndTagToken:
			t := z.Token()
			if t.Data == "table" {
				if isRaw {
					isRaw = false
				}
				if isMissing {
					isMissing = false
				}
			}
		case tt == html.StartTagToken:
			t := z.Token()
			switch {
			case t.Data == "div":
				hh := z.Next()
				if hh == html.TextToken {
					h := z.Token()
					switch h.Data {
					// we are in the Raw Headers now
					case "Raw Headers":
						isRaw = true
						break
					// we are in the missing headers now
					case "Missing Headers":
						isRaw = false
						isMissing = true
						break
					}

				}
			case t.Data == "th":
				hh := z.Next()
				if hh == html.TextToken {
					h := z.Token()
					switch h.Data {
					// save Results according to the current section
					case "X-Frame-Options":
						if isMissing {
							secH.XFrameOptions = hooks.Truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XFrameOptions = hooks.Truncate(h.Data, 300)
						}

					case "Strict-Transport-Security":
						if isMissing {
							secH.StrictTransportSecurity = hooks.Truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.StrictTransportSecurity = hooks.Truncate(h.Data, 300)
						}

					case "X-Content-Type-Options":
						if isMissing {
							secH.XContentTypeOptions = hooks.Truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XContentTypeOptions = hooks.Truncate(h.Data, 300)
						}

					case "X-XSS-Protection":
						if isMissing {
							secH.XXSSProtection = hooks.Truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XXSSProtection = hooks.Truncate(h.Data, 300)
						}

					case "Content-Security-Policy":
						if isMissing {
							secH.ContentSecurityPolicy = hooks.Truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.ContentSecurityPolicy = hooks.Truncate(h.Data, 300)
						}

					case "Referrer-Policy":
						if isMissing {
							secH.ReferrerPolicy = hooks.Truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.ReferrerPolicy = hooks.Truncate(h.Data, 300)
						}

					}
				}

			}

		}
	}

}

func handleScan(domains []hooks.DomainsReachable, internalChannel chan hooks.InternalMessage) []hooks.DomainsReachable {
	for (len(manager.Errors) > 0 || len(domains) > 0) && int(manager.Status.GetCurrentScans()) < manager.MaxParallelScans {
		manager.FirstScan = true
		var scanMsg hooks.InternalMessage
		var retDom = domains
		var scan hooks.DomainsReachable
		// pop fist domain
		if manager.CheckDoError() && len(manager.Errors) != 0 {
			scanMsg, manager.Errors = manager.Errors[0], manager.Errors[1:]
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Retrying failed assessment next: %v", scanMsg.Domain.DomainName), manager.LogLevel, hooks.LogTrace)
		} else if len(domains) != 0 {
			scan, retDom = domains[0], domains[1:]
			scanMsg = hooks.InternalMessage{
				Domain:     scan,
				Results:    nil,
				Retries:    0,
				StatusCode: hooks.InternalNew,
			}
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Trying new assessment next: %v", scanMsg.Domain.DomainName), manager.LogLevel, hooks.LogTrace)
		} else {
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("No new assessment started"), manager.LogLevel, hooks.LogTrace)
			return domains
		}
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Started assessment for %v", scanMsg.Domain.DomainName), manager.LogLevel, hooks.LogDebug)
		go assessment(scanMsg, internalChannel)
		manager.Status.AddCurrentScans(1)
		return retDom
	}
	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("No new assessment started"), manager.LogLevel, hooks.LogTrace)
	return domains
}

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {

	row, err := invokeSecurityHeaders(scan.Domain.DomainName, scan.Domain.TestWithSSL)
	//Ignore mismatch
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Assessment failed for %v: %v", scan.Domain.DomainName, err), manager.LogLevel, hooks.LogError)
		scan.Results = row
		scan.StatusCode = hooks.InternalError
		internalChannel <- scan
		return
	}
	scan.Results = row
	scan.StatusCode = hooks.InternalSuccess
	internalChannel <- scan
}

// invokeSecurityHeaders is called by a LabsReport object to query the securityheaders.io
// API for grading and adds the result to the object
func invokeSecurityHeaders(host string, supportsSSL bool) (TableRow, error) {
	var apiURL string
	var hostURL string

	if supportsSSL {
		hostURL = "https://" + host
	} else {
		hostURL = host
	}
	apiURL = currentConfig.APILocation + hostURL + fmt.Sprintf("&hide=%v&followRedirects=%v", currentConfig.Hidden, currentConfig.FollowRedirect)

	// Get http Header from the securityheaders API to get the grading of the scanned host
	response, err := http.Get(apiURL)
	if err != nil {
		return TableRow{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if manager.LogLevel >= hooks.LogError {
			log.Printf("[ERROR] securityheaders.io returned non-200 status for host %v : %v", host, response.Status)
		}
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Returned non-200 status for host %v : %v", host, response.Status), manager.LogLevel, hooks.LogError)
		err = errors.New("security Header Assessment failed")
		return TableRow{}, err
	}

	// The grading done by securityheaders.io is Base64-encoded, so we decode it and get a JSON object
	grade := response.Header.Get("X-Grade")
	if grade == "" {
		err := fmt.Errorf("decoding X-Grade Header from securityheaders.io")
		return TableRow{}, err
	}
	//Parse the Results
	securityheaders := parseResponse(response.Body)

	securityheaders.Grade = hooks.Truncate(grade, 2)

	return *securityheaders, nil
}

func handleResults(result hooks.InternalMessage) {
	res, ok := result.Results.(TableRow)
	//TODO FIX with error handling
	manager.Status.AddCurrentScans(-1)

	if !ok {
		//TODO Handle Error
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't assert type of result for  %v", result.Domain.DomainName), manager.LogLevel, hooks.LogError)
		res = TableRow{}
		result.StatusCode = hooks.InternalFatalError
	}

	switch result.StatusCode {
	case hooks.InternalFatalError:
		res.ScanStatus = hooks.StatusError
		manager.Status.AddFatalErrorScans(1)
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Assessment of %v failed ultimately", result.Domain.DomainName), manager.LogLevel, hooks.LogInfo)
	case hooks.InternalSuccess:
		res.ScanStatus = hooks.StatusDone
		manager.Status.AddFinishedScans(1)
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Assessment of %v was successful", result.Domain.DomainName), manager.LogLevel, hooks.LogDebug)
	}
	where := hooks.ScanWhereCond{
		DomainID:    result.Domain.DomainID,
		ScanID:      manager.ScanID,
		TestWithSSL: result.Domain.TestWithSSL}
	err := backend.SaveResults(manager.GetTableName(), structs.New(where), structs.New(res))
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't save results for %v: %v", result.Domain.DomainName, err), manager.LogLevel, hooks.LogError)
		return
	}
	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Results for %v saved", result.Domain.DomainName), manager.LogLevel, hooks.LogDebug)
}

func flagSetUp() {
	used = flag.Bool("no-sechead", false, "Don't use the SecurityHeaders.io-Scan")
}

func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage, config interface{}) bool {
	currentScan.SecurityHeaders = !*used
	currentScan.SecurityHeadersVersion = manager.Version
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
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Failed parsing config to interface: %v", err), manager.LogLevel, hooks.LogError)
	}
	err = json.Unmarshal(jsonString, &currentConfig)
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Failed parsing json to struct: %v", err), manager.LogLevel, hooks.LogError)
	}
	if currentConfig.Hidden != "on" && currentConfig.Hidden != "off" {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Hidden in the Config has to be 'on' or 'off' not '%v'", currentConfig.Hidden), manager.LogLevel, hooks.LogCritical)
	}
	if currentConfig.FollowRedirect != "on" && currentConfig.FollowRedirect != "off" {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Hidden in the Config has to be 'on' or 'off' not '%v'", currentConfig.FollowRedirect), manager.LogLevel, hooks.LogCritical)
	}
	manager.MaxRetries = currentConfig.Retries
	manager.ScanType = currentConfig.ScanType
	manager.LogLevel = hooks.ParseLogLevel(currentConfig.LogLevel)
	manager.MaxParallelScans = currentConfig.ParallelScans
}

func continueScan(scan hooks.ScanRow) bool {
	if manager.Version != scan.SecurityHeadersVersion {
		return false
	}
	return true
}

func setUp() {

}
func setUpLogger() {
	manager.Logger = log.New(hooks.LogWriter, "SecHead\t", log.Ldate|log.Ltime)
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

	setUpLogger()
}
