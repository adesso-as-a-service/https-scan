package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/fatih/structs"
	"golang.org/x/net/html"
)

// CrawlerMaxRedirects sets the maximum number of Redirects to be followed
var sechrMaxRedirects uint8 = 10

// crawlerVersion
var sechVersion = "10"

// crawlerManager
var sechManager = Manager{
	3,  //Max Retries
	10, //Max parallel Scans
	crawlerVersion,
	"SecurityHeaders",      //Table name
	scanBoth,               // Scan HTTP and HTTPS
	nil,                    //output channel
	logDebug,               //loglevel
	scanStatus{0, 0, 0, 0}, // initial scanStatus
	0,                   // number of errors while finishing
	0,                   // scanID
	[]internalMessage{}, //errors
	false,               //hasn't started first scan
}

// Securityheaders is the object used for unmarshalling the results by the API
type SechRow struct {
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
func parseResponse(r io.Reader) *SechRow {
	z := html.NewTokenizer(r)
	var secH SechRow
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
							secH.XFrameOptions = truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XFrameOptions = truncate(h.Data, 300)
						}

					case "Strict-Transport-Security":
						if isMissing {
							secH.StrictTransportSecurity = truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.StrictTransportSecurity = truncate(h.Data, 300)
						}

					case "X-Content-Type-Options":
						if isMissing {
							secH.XContentTypeOptions = truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XContentTypeOptions = truncate(h.Data, 300)
						}

					case "X-XSS-Protection":
						if isMissing {
							secH.XXSSProtection = truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XXSSProtection = truncate(h.Data, 300)
						}

					case "Content-Security-Policy":
						if isMissing {
							secH.ContentSecurityPolicy = truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.ContentSecurityPolicy = truncate(h.Data, 300)
						}

					case "Referrer-Policy":
						if isMissing {
							secH.ReferrerPolicy = truncate("missing", 300)
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.ReferrerPolicy = truncate(h.Data, 300)
						}

					}
				}

			}

		}
	}

}

func (manager *Manager) sechHandleScan(domains []DomainsReachable, internalChannel chan internalMessage) []DomainsReachable {
	for len(domains) > 0 && int(manager.status.getCurrentScans()) < manager.maxParallelScans {
		manager.firstScan = true
		// pop fist domain
		scan, retDom := domains[0], domains[1:]
		scanMsg := internalMessage{scan, nil, 0, internalNew}
		go manager.sechAssessment(scanMsg, internalChannel)
		manager.status.addCurrentScans(1)
		return retDom
	}
	return domains
}

func (manager *Manager) sechAssessment(scan internalMessage, internalChannel chan internalMessage) {

	row, err := invokeSecurityHeaders(scan.domain.DomainName, scan.domain.TestWithSSL)
	//Ignore mismatch
	if err != nil {
		//TODO Handle Error
		log.Printf("securityheader couldn't get for %d: %s", scan.domain.DomainID, err.Error())
		scan.results = row
		scan.statusCode = internalFatalError
		internalChannel <- scan
		return
	}
	scan.results = row
	scan.statusCode = internalSuccess
	internalChannel <- scan
}

// invokeSecurityHeaders is called by a LabsReport object to query the securityheaders.io
// API for grading and adds the result to the object
func invokeSecurityHeaders(host string, supportsSSL bool) (SechRow, error) {
	var apiURL string
	var hostURL string

	if supportsSSL {
		hostURL = "https://" + host
		apiURL = "https://securityheaders.io/?q=" + hostURL + "&hide=on&followRedirects=off"
	} else {
		hostURL = "http://" + host
		apiURL = "https://securityheaders.io/?q=" + hostURL + "&hide=on&followRedirects=off"
	}

	if logLevel >= logInfo {
		log.Printf("[INFO] Getting securityheaders.io assessment: %v", host)
	}

	// Get http Header from the securityheaders API to get the grading of the scanned host
	response, err := http.Get(apiURL)
	if err != nil {
		return SechRow{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if logLevel >= logError {
			log.Printf("[ERROR] securityheaders.io returned non-200 status for host %v : %v", host, response.Status)
		}
		err = errors.New("security Header Assessment failed")
		return SechRow{}, err
	}

	// The grading done by securityheaders.io is Base64-encoded, so we decode it and get a JSON object
	grade := response.Header.Get("X-Grade")
	if grade == "" {
		err := fmt.Errorf("[ERROR] Decoding X-Grade Header from securityheaders.io")
		return SechRow{}, err
	}
	//Parse the Results
	securityheaders := parseResponse(response.Body)

	securityheaders.Grade = truncate(grade, 2)

	return *securityheaders, nil
}

func (manager *Manager) sechHandleResults(result internalMessage) {
	res, ok := result.results.(SechRow)
	//TODO FIX with error handling
	manager.status.addCurrentScans(-1)

	if !ok {
		//TODO Handle Error

		log.Print("sech manager couldn't assert type")
		res = SechRow{}
		result.statusCode = internalFatalError
	}

	switch result.statusCode {
	case internalFatalError:
		res.ScanStatus = statusError
		manager.status.addErrorScans(1)
	case internalSuccess:
		res.ScanStatus = statusDone
		manager.status.addFinishedScans(1)
	}
	where := ScanWhereCond{result.domain.DomainID, manager.scanID, result.domain.TestWithSSL}
	err := saveResults(manager.getTableName(), structs.New(where), structs.New(res))
	if err != nil {
		//TODO Handle Error
		log.Printf("sech couldn't save results for %s: %s", result.domain.DomainName, err.Error())
		return
	}
}
