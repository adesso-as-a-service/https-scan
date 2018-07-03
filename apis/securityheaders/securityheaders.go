package securityheaders

import (
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
var maxScans = 10

// crawlerVersion
var version = "10"

var used *bool

var maxRetries *int

var manager = hooks.Manager{
	MaxRetries:       3,        //Max Retries
	MaxParallelScans: maxScans, //Max parallel Scans
	Version:          version,
	Table:            "Securityheaders",         //Table name
	ScanType:         hooks.ScanOnePreferHTTP,   // Scan HTTP or HTTPS
	OutputChannel:    nil,                       //output channel
	LogLevel:         hooks.LogNotice,           //loglevel
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
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
	for len(domains) > 0 && int(manager.Status.GetCurrentScans()) < manager.MaxParallelScans {
		manager.FirstScan = true
		// pop fist domain
		scan, retDom := domains[0], domains[1:]
		scanMsg := hooks.InternalMessage{
			Domain:     scan,
			Results:    nil,
			Retries:    0,
			StatusCode: hooks.InternalNew,
		}
		go assessment(scanMsg, internalChannel)
		manager.Status.AddCurrentScans(1)
		return retDom
	}
	return domains
}

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {

	row, err := invokeSecurityHeaders(scan.Domain.DomainName, scan.Domain.TestWithSSL)
	//Ignore mismatch
	if err != nil {
		//TODO Handle Error
		log.Printf("securityheader couldn't get for %d: %s", scan.Domain.DomainID, err.Error())
		scan.Results = row
		scan.StatusCode = hooks.InternalFatalError
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
		apiURL = "https://securityheaders.io/?q=" + hostURL + "&hide=on&followRedirects=off"
	} else {
		hostURL = "http://" + host
		apiURL = "https://securityheaders.io/?q=" + hostURL + "&hide=on&followRedirects=off"
	}

	if manager.LogLevel >= hooks.LogInfo {
		log.Printf("[INFO] Getting securityheaders.io assessment: %v", host)
	}

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
		err = errors.New("security Header Assessment failed")
		return TableRow{}, err
	}

	// The grading done by securityheaders.io is Base64-encoded, so we decode it and get a JSON object
	grade := response.Header.Get("X-Grade")
	if grade == "" {
		err := fmt.Errorf("[ERROR] Decoding X-Grade Header from securityheaders.io")
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

		log.Print("sech manager couldn't assert type")
		res = TableRow{}
		result.StatusCode = hooks.InternalFatalError
	}

	switch result.StatusCode {
	case hooks.InternalFatalError:
		res.ScanStatus = hooks.StatusError
		manager.Status.AddErrorScans(1)
	case hooks.InternalSuccess:
		res.ScanStatus = hooks.StatusDone
		manager.Status.AddFinishedScans(1)
	}
	where := hooks.ScanWhereCond{
		DomainID:    result.Domain.DomainID,
		ScanID:      manager.ScanID,
		TestWithSSL: result.Domain.TestWithSSL}
	err := backend.SaveResults(manager.GetTableName(), structs.New(where), structs.New(res))
	if err != nil {
		//TODO Handle Error
		log.Printf("sech couldn't save results for %s: %s", result.Domain.DomainName, err.Error())
		return
	}
}

func flagSetUp() {
	used = flag.Bool("no-sechead", false, "Don't use the SecurityHeaders.io-Scan")
	maxRetries = flag.Int("sechead-retries", 3, "Number of retries for the SecurityHeaders.io-Scan")
}

func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage) bool {
	currentScan.SecurityHeaders = !*used
	currentScan.SecurityHeadersVersion = manager.Version
	if !*used {
		if manager.MaxParallelScans != 0 {
			manager.MaxRetries = *maxRetries
			manager.OutputChannel = channel
			return true
		}
	}
	return false
}

func continueScan(scan hooks.ScanRow) bool {
	if manager.Version != scan.SecurityHeadersVersion {
		return false
	}
	return true
}

func setUp() {

}

func init() {
	hooks.ManagerMap[manager.Table] = &manager

	hooks.FlagSetUp[manager.Table] = flagSetUp

	hooks.ConfigureSetUp[manager.Table] = configureSetUp

	hooks.ContinueScan[manager.Table] = continueScan

	hooks.ManagerSetUp[manager.Table] = setUp

	hooks.ManagerHandleScan[manager.Table] = handleScan

	hooks.ManagerHandleResults[manager.Table] = handleResults

}
