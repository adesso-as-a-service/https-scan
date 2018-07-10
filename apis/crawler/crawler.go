package crawler

//Done

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/structs"

	"../../backend"
	"../../hooks"
)

// TableRow represents the scan results for the crawler table
type TableRow struct {
	Redirects   int
	StatusCodes string
	URLs        string
	ScanStatus  int
}

// CrawlerMaxRedirects sets the maximum number of Redirects to be followed
var maxRedirects uint8 = 10

var maxScans = 10

var used *bool

// crawlerVersion
var version = "10"

var maxRetries *int

// crawlerManager
var manager = hooks.Manager{
	MaxRetries:       3,        //Max Retries
	MaxParallelScans: maxScans, //Max parallel Scans
	Version:          version,
	Table:            "Crawler",                 //Table name
	ScanType:         hooks.ScanBoth,            // Scan HTTP or HTTPS
	OutputChannel:    nil,                       //output channel
	LogLevel:         hooks.LogNotice,           //loglevel
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
}

func getBaseURL(myURL string) string {
	u, _ := url.Parse(myURL)
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func openURL(myURL string) (TableRow, error) {
	var urls []string
	var rCodes []string
	var results TableRow
	var i = uint8(0)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
		Timeout:   time.Duration(30) * time.Second,
	}
	for i < maxRedirects {
		resp, err := client.Head(myURL)
		if err != nil && err != http.ErrUseLastResponse {
			return results, err
		}
		urls = append(urls, myURL)
		rCodes = append(rCodes, fmt.Sprintf("%d", resp.StatusCode))

		if resp.StatusCode/100 == 3 {
			help := resp.Header.Get("Location")
			u, _ := url.Parse(help)
			if u.IsAbs() {
				myURL = help
			} else {
				if help[0] == '/' {
					myURL = getBaseURL(myURL) + help
				} else {
					myURL = myURL + "/" + help
				}
			}
			i++
		} else {
			break
		}
	}

	results.URLs = hooks.Truncate(strings.Join(urls, "->"), 1000)
	results.StatusCodes = hooks.Truncate(strings.Join(rCodes, "->"), 50)
	results.Redirects = len(urls) - 1

	return results, nil
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
	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("no new Assessment started"), manager.LogLevel, hooks.LogTrace)
	return domains
}

func handleResults(result hooks.InternalMessage) {
	res, ok := result.Results.(TableRow)
	manager.Status.AddCurrentScans(-1)

	if !ok {
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
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Assessment of %v was successful", result.Domain.DomainName), manager.LogLevel, hooks.LogDebug)
		manager.Status.AddFinishedScans(1)
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

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {
	var url string
	if scan.Domain.TestWithSSL {
		url = "https://" + scan.Domain.DomainName
	} else {
		url = "http://" + scan.Domain.DomainName
	}
	row, err := openURL(url)
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

func flagSetUp() {
	used = flag.Bool("no-crawler", false, "Don't use the redirect crawler")
	maxRetries = flag.Int("crawler-retries", 3, "Number of retries for the redirect crawler")
}

func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage) bool {
	currentScan.Crawler = !*used
	currentScan.CrawlerVersion = manager.Version
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
	if manager.Version != scan.CrawlerVersion {
		return false
	}
	return true
}

func setUp() {

}

func setUpLogger() {
	manager.Logger = log.New(hooks.LogWriter, "Crawler\t", log.Ldate|log.Ltime)
}

func init() {
	hooks.ManagerMap[manager.Table] = &manager

	hooks.FlagSetUp[manager.Table] = flagSetUp

	hooks.ConfigureSetUp[manager.Table] = configureSetUp

	hooks.ContinueScan[manager.Table] = continueScan

	hooks.ManagerSetUp[manager.Table] = setUp

	hooks.ManagerHandleScan[manager.Table] = handleScan

	hooks.ManagerHandleResults[manager.Table] = handleResults

	setUpLogger()

}
