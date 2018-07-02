package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/structs"
)

// CrawlerTableRow represents the scan results for the crawler table
type CrawlerTableRow struct {
	Redirects   int
	StatusCodes string
	URLs        string
	ScanStatus  int
}

// CrawlerMaxRedirects sets the maximum number of Redirects to be followed
var crawlerMaxRedirects uint8 = 10

// crawlerVersion
var crawlerVersion = "10"

// crawlerManager
var crawlerManager = Manager{
	3,  //Max Retries
	10, //Max parallel Scans
	crawlerVersion,
	"Crawler",              //Table name
	scanBoth,               // Scan HTTP and HTTPS
	nil,                    //output channel
	logDebug,               //loglevel
	scanStatus{0, 0, 0, 0}, // initial scanStatus
	0,                   // number of errors while finishing
	0,                   // scanID
	[]internalMessage{}, //errors
	false,               //hasn't started first scan
}

func getBaseURL(myURL string) string {
	//TODO ERROR HANDLING
	u, _ := url.Parse(myURL)
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func crawlerOpenURL(myURL string) (CrawlerTableRow, error) {
	var urls []string
	var rCodes []string
	var results CrawlerTableRow
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
	for i < crawlerMaxRedirects {
		resp, err := client.Head(myURL)
		if err != nil && err != http.ErrUseLastResponse {
			fmt.Printf("Something wrong here %s\n", myURL)
			//TODO error handling
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

	results.URLs = truncate(strings.Join(urls, "->"), 1000)
	results.StatusCodes = truncate(strings.Join(rCodes, "->"), 50)
	results.Redirects = len(urls) - 1

	return results, nil
}

func (manager *Manager) crawlerHandleScan(domains []DomainsReachable, internalChannel chan internalMessage) []DomainsReachable {
	for len(domains) > 0 && int(manager.status.getCurrentScans()) < manager.maxParallelScans {
		manager.firstScan = true
		// pop fist domain
		scan, retDom := domains[0], domains[1:]
		scanMsg := internalMessage{scan, nil, 0, internalNew}
		go manager.crawlerAssessment(scanMsg, internalChannel)
		manager.status.addCurrentScans(1)
		return retDom
	}
	return domains
}

func (manager *Manager) crawlerHandleResults(result internalMessage) {
	res, ok := result.results.(CrawlerTableRow)
	//TODO FIX with error handling
	manager.status.addCurrentScans(-1)

	if !ok {
		//TODO Handle Error

		log.Print("crawler manager couldn't assert type")
		res = CrawlerTableRow{}
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
		log.Printf("crawler couldn't save results for %s: %s", result.domain.DomainName, err.Error())
		return
	}
}

func (manager *Manager) crawlerAssessment(scan internalMessage, internalChannel chan internalMessage) {
	var url string
	if scan.domain.TestWithSSL {
		url = "https://" + scan.domain.DomainName
	} else {
		url = "http://" + scan.domain.DomainName
	}
	row, err := crawlerOpenURL(url)
	//Ignore mismatch
	if err != nil {
		//TODO Handle Error
		log.Printf("crawler couldn't get for %d: %s", scan.domain.DomainID, err.Error())
		scan.results = row
		scan.statusCode = internalFatalError
		internalChannel <- scan
		return
	}
	scan.results = row
	scan.statusCode = internalSuccess
	internalChannel <- scan
}
