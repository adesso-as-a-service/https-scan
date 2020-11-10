package securityheaders

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"../../backend"
	"../../hooks"
	"github.com/fatih/structs"
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
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
	LoggingTag:       "sechead",
}

// CrawlerConfig
type Config struct {
	Retries        int
	ScanType       int
	ParallelScans  int
	Hidden         string
	FollowRedirect string
	APILocation    string
}

// defaultConfig
var currentConfig = Config{
	Retries:        3,
	ScanType:       hooks.ScanBoth,
	APILocation:    "https://securityheaders.com/?q=",
	ParallelScans:  10,
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
	FeaturePolicy           string
	ExpectCT                string
	ReportTo                string
	NEL                     string
	ScanStatus              int
}

func getTextExcerpt(tableContent string, tableName string) string {

	beginOfTable := strings.Index(tableContent, tableName)
	if beginOfTable == -1 {
		return ""
	}
	table := tableContent[beginOfTable:]
	endOfTable := strings.Index(table, "</table>")
	table = table[:endOfTable]

	beginOftbody := strings.Index(table, "<tbody>")
	table = table[beginOftbody:]
	endOftbody := strings.Index(table, "</tbody>")
	table = table[:endOftbody]

	return table
}

func findHeaders(rawHeadersText string, headerName string) string {
	// Search with the closing HTML tag to avoid findings in
	// the value section
	searchText := headerName + "</th>"

	textBegin := strings.Index(rawHeadersText, searchText)
	if textBegin == -1 {
		return "not implemented"
	}

	// Remove all exept the line with the header
	header := rawHeadersText[textBegin:]
	textEnd := strings.Index(header, "</tr>")
	header = header[:textEnd]

	textBegin = strings.Index(header, "<td")
	header = header[textBegin+len("<td"):]

	textBegin = strings.Index(header, ">")
	header = header[textBegin+len(">"):]

	textEnd = strings.Index(header, "</td>")
	header = header[:textEnd]

	//Clean results from tags
	noTags := regexp.MustCompile("<[/A-Z-Za-z-z]+>")
	header = noTags.ReplaceAllString(header, "")

	//Find header
	onlyData := regexp.MustCompile(".*")
	header = onlyData.FindString(header)

	return header
}

func parseResponse(r io.ReadCloser) *TableRow {
	var secH TableRow

	bytesStream, _ := ioutil.ReadAll(r)
	bodyContent := string(bytesStream)

	rawHeadersContent := getTextExcerpt(bodyContent, "Raw Headers")
	missingHeadersContent := getTextExcerpt(bodyContent, "Missing Headers")

	secH.StrictTransportSecurity = searchForHeaders(rawHeadersContent, missingHeadersContent, "Strict-Transport-Security")
	secH.XXSSProtection = searchForHeaders(rawHeadersContent, missingHeadersContent, "X-XSS-Protection")
	secH.XFrameOptions = searchForHeaders(rawHeadersContent, missingHeadersContent, "X-Frame-Options")
	secH.ContentSecurityPolicy = searchForHeaders(rawHeadersContent, missingHeadersContent, "Content-Security-Policy")
	secH.XContentTypeOptions = searchForHeaders(rawHeadersContent, missingHeadersContent, "X-Content-Type-Options")
	secH.ReferrerPolicy = searchForHeaders(rawHeadersContent, missingHeadersContent, "Referrer-Policy")
	secH.FeaturePolicy = searchForHeaders(rawHeadersContent, missingHeadersContent, "Feature-Policy")
	secH.ExpectCT = searchForHeaders(rawHeadersContent, missingHeadersContent, "Expect-CT")
	secH.ReportTo = searchForHeaders(rawHeadersContent, missingHeadersContent, "Report-To")
	secH.NEL = searchForHeaders(rawHeadersContent, missingHeadersContent, "NEL")

	return &secH
}

func searchForHeaders(rawHeadersContent string, missingHeadersContent string, headerName string) string {
	result := ""
	rawHeaders := ""
	missingHeaders := ""

	rawHeaders = findHeaders(rawHeadersContent, headerName)
	missingHeaders = findHeaders(missingHeadersContent, headerName)
	if rawHeaders == "not implemented" || missingHeaders != "not implemented" {
		result = "missing"
	} else {
		if headerName == "Content-Security-Policy" {
			result = hooks.Truncate(rawHeaders, 5000)
		} else {
			result = hooks.Truncate(rawHeaders, 300)
		}
		result = strings.ReplaceAll(result, "&quot;", "\"")
	}
	return result
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
	manager.Logger.Tracef("No new assessment started")
	return domains
}

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {

	row, err := invokeSecurityHeaders(scan.Domain.DomainName, scan.Domain.TestWithSSL)
	//Ignore mismatch
	if err != nil {
		manager.Logger.Errorf("Assessment failed for %v: %v", scan.Domain.DomainName, err)
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
	//apiURL = currentConfig.APILocation + hostURL + fmt.Sprintf("&hide=%v&followRedirects=%v", currentConfig.Hidden, currentConfig.FollowRedirect)
	apiURL = currentConfig.APILocation + hostURL + fmt.Sprintf("&hide=%s&followRedirects=%s", currentConfig.Hidden, currentConfig.FollowRedirect)

	// Get http Header from the securityheaders API to get the grading of the scanned host
	response, err := http.Get(apiURL)

	//temp b
	securityheaders := parseResponse(response.Body)
	//temp e
	if err != nil {
		return TableRow{}, err
	}
	if response.StatusCode != http.StatusOK {
		manager.Logger.Errorf("Returned non-200 status for host %v : %v", host, response.Status)
		err = errors.New("security Header Assessment failed")
		io.Copy(ioutil.Discard, response.Body)
		//response.Body.Close()
		return TableRow{}, err
	}
	io.Copy(ioutil.Discard, response.Body)
	//response.Body.Close()
	// The grading done by securityheaders.io is Base64-encoded, so we decode it and get a JSON object
	grade := response.Header.Get("X-Grade")
	if grade == "" {
		err := fmt.Errorf("decoding X-Grade Header from securityheaders.io")
		return TableRow{}, err
	}

	//Parse the Results
	//securityheaders := parseResponse(response.Body)

	securityheaders.Grade = hooks.Truncate(grade, 2)

	return *securityheaders, nil
}

func handleResults(result hooks.InternalMessage) {
	res, ok := result.Results.(TableRow)
	//TODO FIX with error handling
	manager.Status.AddCurrentScans(-1)

	if !ok {
		//TODO Handle Error
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
		manager.Status.AddFinishedScans(1)
		manager.Logger.Debugf("Assessment of %v was successful", result.Domain.DomainName)
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
		manager.Logger.Errorf("Failed parsing config to interface: %v", err)
	}
	err = json.Unmarshal(jsonString, &currentConfig)
	if err != nil {
		manager.Logger.Errorf("Failed parsing json to struct: %v", err)
	}
	if currentConfig.Hidden != "on" && currentConfig.Hidden != "off" {
		manager.Logger.Panicf("Hidden in the Config has to be 'on' or 'off' not '%v'", currentConfig.Hidden)
	}
	if currentConfig.FollowRedirect != "on" && currentConfig.FollowRedirect != "off" {
		manager.Logger.Panicf("Hidden in the Config has to be 'on' or 'off' not '%v'", currentConfig.FollowRedirect)
	}
	manager.MaxRetries = currentConfig.Retries
	manager.ScanType = currentConfig.ScanType
	manager.MaxParallelScans = currentConfig.ParallelScans
}

func continueScan(scan hooks.ScanRow) bool {
	return manager.Version == scan.SecurityHeadersVersion
}

func setUp() {
	var logger = hooks.Logger
	manager.Logger = logger.WithField("hook", manager.LoggingTag)
}

func setUpLogger() {

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
