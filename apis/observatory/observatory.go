package observatory

//Done

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"../../backend"
	"../../hooks"
	"github.com/fatih/structs"
)

type TableRow struct {
	Grade         string
	Score         int
	TestsFailed   int
	TestsPassed   int
	TestsQuantity int

	CSPPassed bool
	CSPEval   uint16
	CSPResult string
	CSPDesc   string

	CookiesPassed bool
	CookiesResult string
	CookiesDesc   string

	CORSPassed bool
	CORSResult string
	CORSDesc   string

	HPKPPassed bool
	HPKPResult string
	HPKPDesc   string

	RedirectionPassed bool
	RedirectionResult string
	RedirectionDesc   string

	HSTSPassed bool
	HSTSResult string
	HSTSDesc   string

	SRIPassed bool
	SRIResult string
	SRIDesc   string

	XContentTypePassed bool
	XContentTypeResult string
	XContentTypeDesc   string

	XFrameOptionsPassed bool
	XFrameOptionsResult string
	XFrameOptionsDesc   string

	XXSSProtectionPassed bool
	XXSSProtectionResult string
	XXSSProtectionDesc   string

	ScanStatus int
}

// maximum Number of parallel Scans
var maxScans int = 5

// crawlerVersion
var version = "10"

var used *bool

var maxRetries *int

var logger *log.Logger

var manager = hooks.Manager{
	MaxRetries:       3,        //Max Retries
	MaxParallelScans: maxScans, //Max parallel Scans
	Version:          version,
	Table:            "Observatory",             //Table name
	ScanType:         hooks.ScanOnePreferSSL,    // Scan HTTP or HTTPS
	OutputChannel:    nil,                       //output channel
	LogLevel:         hooks.LogNotice,           //loglevel
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
}

type Policy struct {
	AntiClickjacking      bool
	DefaultNone           bool
	InsecureBaseUri       bool
	InsecureFormAction    bool
	InsecureSchemeActive  bool
	InsecureSchemePassive bool
	StrictDynamic         bool
	UnsafeEval            bool
	UnsafeInline          bool
	UnsafeInlineStyle     bool
	UnsafeObjects         bool
}

type Cookie struct {
	Domain   string
	Expires  *int64
	Httponly bool
	MaxAge   *int64 `json:"max-age"`
	Path     string
	Port     *int
	Samesite bool
	Secure   bool
}

// AnalyzeResult is the object to contain the response we get
// From starting an Observatory-Scan
type AnalyzeResult struct {
	EndTime         string `json:"end_time"`
	Grade           string `json:"grade"`
	ResponseHeaders struct {
		CacheControl     string `json:"Cache-Control"`
		Connection       string `json:"Connection"`
		ContentType      string `json:"Content-Type"`
		Date             string `json:"Date"`
		Expires          string `json:"Expires"`
		Server           string `json:"Server"`
		TransferEncoding string `json:"Transfer-Encoding"`
	} `json:"response_headers"`
	ScanID        int    `json:"scan_id"`
	Score         int    `json:"score"`
	StartTime     string `json:"start_time"`
	State         string `json:"state"`
	TestsFailed   int    `json:"tests_failed"`
	TestsPassed   int    `json:"tests_passed"`
	TestsQuantity int    `json:"tests_quantity"`
}

// ScanResults are the results we get once we have a finished scan and
// Query the API for our results
type ScanResults struct {
	ContentSecurityPolicy struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data   map[string][]string
			Http   bool
			Meta   bool
			Policy Policy
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"content-security-policy"`
	Contribute struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data interface{} `json:"data"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"contribute"`
	Cookies struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data     map[string]Cookie
			SameSite *bool
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"cookies"`
	CrossOriginResourceSharing struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data struct {
				Acao               interface{} `json:"acao"`
				Clientaccesspolicy interface{} `json:"clientaccesspolicy"`
				Crossdomain        interface{} `json:"crossdomain"`
			} `json:"data"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"cross-origin-resource-sharing"`
	PublicKeyPinning struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data              interface{} `json:"data"`
			IncludeSubDomains bool        `json:"includeSubDomains"`
			MaxAge            interface{} `json:"max-age"`
			NumPins           interface{} `json:"numPins"`
			Preloaded         bool        `json:"preloaded"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"public-key-pinning"`
	Redirection struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Destination string   `json:"destination"`
			Redirects   bool     `json:"redirects"`
			Route       []string `json:"route"`
			StatusCode  int      `json:"status_code"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"redirection"`
	StrictTransportSecurity struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data              interface{} `json:"data"`
			IncludeSubDomains bool        `json:"includeSubDomains"`
			MaxAge            interface{} `json:"max-age"`
			Preload           bool        `json:"preload"`
			Preloaded         bool        `json:"preloaded"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"strict-transport-security"`
	SubresourceIntegrity struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data struct {
			} `json:"data"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"subresource-integrity"`
	XContentTypeOptions struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data interface{} `json:"data"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"x-content-type-options"`
	XFrameOptions struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data interface{} `json:"data"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"x-frame-options"`
	XXSSProtection struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data interface{} `json:"data"`
		} `json:"output"`
		Pass             bool   `json:"pass"`
		Result           string `json:"result"`
		ScoreDescription string `json:"score_description"`
		ScoreModifier    int    `json:"score_modifier"`
	} `json:"x-xss-protection"`
}

// invokeObservatoryAnalyzation starts an HTTP-Observatory assessment and polls
// To see if the scan is done, then adding the result to the calling LabsReport object
func invokeObservatoryAnalyzation(host string) (AnalyzeResult, error) {
	apiURL := "https://http-observatory.security.mozilla.org/api/v1/analyze?host=" + host
	var analyzeResult AnalyzeResult

	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Getting observatory analyzation: %v", host), manager.LogLevel, hooks.LogTrace)

	// Initiate the scan request, the body of the request contains information to hide the scan from the front-page
	_, err := http.Post(apiURL, "application/x-www-form-urlencoded", strings.NewReader("hidden=true&rescan=false"))
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Received error invoking observatory API for %v : %v", host, err), manager.LogLevel, hooks.LogDebug)
		return AnalyzeResult{}, err
	}

	// Poll every 5 seconds until scan is done, aborting on abnormal or failed states
	for {
		response, err := http.Get(apiURL)
		if err != nil {
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Received error polling observatory API for %v : %v", host, err), manager.LogLevel, hooks.LogWarning)
			return AnalyzeResult{}, err
		}
		defer response.Body.Close()
		analyzeBody, err := ioutil.ReadAll(response.Body)
		err = json.Unmarshal(analyzeBody, &analyzeResult)

		if err != nil {
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Failed unmarshalling analyzeBody for %v: %v", host, err), manager.LogLevel, hooks.LogWarning)
			return AnalyzeResult{}, err
		}
		switch analyzeResult.State {
		case "FINISHED":
			return analyzeResult, nil
		case "ABORTED":
			observatoryStateError := errors.New("Observatory scan aborted for technical reasons at observatory API")
			return AnalyzeResult{}, observatoryStateError
		case "FAILED":
			observatoryStateError := errors.New("Failed to request observatory scan")
			return AnalyzeResult{}, observatoryStateError
		case "PENDING", "RUNNING", "STARTING":
			time.Sleep(5 * time.Second)
			continue
		default:
			observatoryStateError := errors.New("Could not request observatory scan")
			return AnalyzeResult{}, observatoryStateError
		}
	}
}

// InvokeObservatoryResults gets the results of an already done scan and
// And adds them to the calling LabsReport object
func invokeObservatoryResults(analyzeResults AnalyzeResult) (ScanResults, error) {
	var scanResults ScanResults
	// Getting the results of an unfinished scan won't work -- abort
	if analyzeResults.State != "FINISHED" {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Tried accessing results before the scan finished"), manager.LogLevel, hooks.LogWarning)
		return ScanResults{}, errors.New("Invoked results without finished analysis")
	}

	resultApiUrl := "https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan=" + strconv.Itoa(analyzeResults.ScanID)
	response, err := http.Get(resultApiUrl)
	if err != nil {
		return ScanResults{}, err
	}
	resultsBody, err := ioutil.ReadAll(response.Body)
	// Since we're getting a JSON as a response, unmarshal it into a new ObservatoryScanResults object
	// And add it to our calling LabsReport-Object
	err = json.Unmarshal(resultsBody, &scanResults)
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Failed unmarshalling results: %v", err), manager.LogLevel, hooks.LogWarning)
		return ScanResults{}, err
	}
	return scanResults, nil
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

func parseCSP(policy Policy) uint16 {
	var ret uint16

	if !policy.AntiClickjacking {
		ret = ret | 1
	}

	if !policy.DefaultNone {
		ret = ret | (1 << 1)
	}

	if policy.InsecureBaseUri {
		ret = ret | (1 << 2)
	}

	if policy.InsecureFormAction {
		ret = ret | (1 << 3)
	}

	if policy.InsecureSchemeActive {
		ret = ret | (1 << 4)
	}

	if policy.InsecureSchemePassive {
		ret = ret | (1 << 5)
	}

	if policy.StrictDynamic {
		ret = ret | (1 << 6)
	}

	if policy.UnsafeEval {
		ret = ret | (1 << 7)
	}

	if policy.UnsafeInline {
		ret = ret | (1 << 8)
	}

	if policy.UnsafeInlineStyle {
		ret = ret | (1 << 9)
	}

	if policy.UnsafeObjects {
		ret = ret | (1 << 10)
	}

	return ret
}

func parseResult(obsResult ScanResults, obsAnaly AnalyzeResult) TableRow {
	var row TableRow

	row.Grade = hooks.Truncate(obsAnaly.Grade, 2)
	row.Score = obsAnaly.Score

	row.TestsFailed = obsAnaly.TestsFailed
	row.TestsPassed = obsAnaly.TestsPassed
	row.TestsQuantity = obsAnaly.TestsQuantity

	row.CSPPassed = obsResult.ContentSecurityPolicy.Pass
	row.CSPEval = parseCSP(obsResult.ContentSecurityPolicy.Output.Policy)
	row.CSPDesc = hooks.Truncate(obsResult.ContentSecurityPolicy.ScoreDescription, 250)
	row.CSPResult = hooks.Truncate(obsResult.ContentSecurityPolicy.Result, 100)

	row.CookiesPassed = obsResult.Cookies.Pass
	row.CookiesDesc = hooks.Truncate(obsResult.Cookies.ScoreDescription, 250)
	row.CookiesResult = hooks.Truncate(obsResult.Cookies.Result, 100)

	row.CORSPassed = obsResult.CrossOriginResourceSharing.Pass
	row.CORSDesc = hooks.Truncate(obsResult.CrossOriginResourceSharing.ScoreDescription, 250)
	row.CORSResult = hooks.Truncate(obsResult.CrossOriginResourceSharing.Result, 100)

	row.HPKPPassed = obsResult.PublicKeyPinning.Pass
	row.HPKPDesc = hooks.Truncate(obsResult.PublicKeyPinning.ScoreDescription, 250)
	row.HPKPResult = hooks.Truncate(obsResult.PublicKeyPinning.Result, 100)

	row.RedirectionPassed = obsResult.Redirection.Pass
	row.RedirectionDesc = hooks.Truncate(obsResult.Redirection.ScoreDescription, 250)
	row.RedirectionResult = hooks.Truncate(obsResult.Redirection.Result, 100)

	row.HSTSPassed = obsResult.StrictTransportSecurity.Pass
	row.HSTSDesc = hooks.Truncate(obsResult.StrictTransportSecurity.ScoreDescription, 250)
	row.HSTSResult = hooks.Truncate(obsResult.StrictTransportSecurity.Result, 100)

	row.SRIPassed = obsResult.SubresourceIntegrity.Pass
	row.SRIDesc = hooks.Truncate(obsResult.SubresourceIntegrity.ScoreDescription, 250)
	row.SRIResult = hooks.Truncate(obsResult.SubresourceIntegrity.Result, 100)

	row.XContentTypePassed = obsResult.XContentTypeOptions.Pass
	row.XContentTypeDesc = hooks.Truncate(obsResult.XContentTypeOptions.ScoreDescription, 250)
	row.XContentTypeResult = hooks.Truncate(obsResult.XContentTypeOptions.Result, 100)

	row.XFrameOptionsPassed = obsResult.XFrameOptions.Pass
	row.XFrameOptionsDesc = hooks.Truncate(obsResult.XFrameOptions.ScoreDescription, 250)
	row.XFrameOptionsResult = hooks.Truncate(obsResult.XFrameOptions.Result, 100)

	row.XXSSProtectionPassed = obsResult.XXSSProtection.Pass
	row.XXSSProtectionDesc = hooks.Truncate(obsResult.XXSSProtection.ScoreDescription, 250)
	row.XXSSProtectionResult = hooks.Truncate(obsResult.XXSSProtection.Result, 100)
	return row
}

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {
	analyze, err := invokeObservatoryAnalyzation(scan.Domain.DomainName)
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't start scan for %v: %v", scan.Domain.DomainName, err), manager.LogLevel, hooks.LogError)
		scan.Results = TableRow{}
		scan.StatusCode = hooks.InternalError
		internalChannel <- scan
		return
	}

	results, err := invokeObservatoryResults(analyze)

	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't get results from API for %v: %v", scan.Domain.DomainName, err), manager.LogLevel, hooks.LogError)
		scan.Results = TableRow{}
		scan.StatusCode = hooks.InternalError
		internalChannel <- scan
		return
	}

	row := parseResult(results, analyze)

	scan.Results = row
	scan.StatusCode = hooks.InternalSuccess
	internalChannel <- scan
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
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Assessment of %v was successful", result.Domain.DomainName), manager.LogLevel, hooks.LogDebug)
		res.ScanStatus = hooks.StatusDone
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

func flagSetUp() {
	used = flag.Bool("no-obs", false, "Don't use the mozilla-observatory-Scan")
	maxRetries = flag.Int("obs-retries", 3, "Number of retries for the mozilla-observatory-Scan")
}

func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage) bool {
	currentScan.Observatory = !*used
	currentScan.ObservatoryVersion = manager.Version
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
	if manager.Version != scan.ObservatoryVersion {
		return false
	}
	return true
}

func setUp() {

}

func setUpLogger() {
	manager.Logger = log.New(hooks.LogWriter, "Observa\t", log.Ldate|log.Ltime)
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
