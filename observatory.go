package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/structs"
)

type ObsTableRow struct {
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

// ObservatoryMaxRedirects sets the maximum number of Redirects to be followed
var obsMaxRedirects uint8 = 10

// crawlerVersion
var obsVersion = "10"

// crawlerManager
var obsManager = Manager{
	3,  //Max Retries
	10, //Max parallel Scans
	crawlerVersion,
	"Observatory",          //Table name
	scanOnePreferHTTP,      // Scan HTTP or HTTPS
	nil,                    //output channel
	logDebug,               //loglevel
	scanStatus{0, 0, 0, 0}, // initial scanStatus
	0,                   // number of errors while finishing
	0,                   // scanID
	[]internalMessage{}, //errors
	false,               //hasn't started first scan
}

type ObsPolicy struct {
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

type ObsCookie struct {
	Domain   string
	Expires  *int64
	Httponly bool
	MaxAge   *int64 `json:"max-age"`
	Path     string
	Port     *int
	Samesite bool
	Secure   bool
}

// ObservatoryAnalyzeResult is the object to contain the response we get
// From starting an Observatory-Scan
type ObsAnalyzeResult struct {
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

// ObservatoryScanResults are the results we get once we have a finished scan and
// Query the API for our results
type ObsScanResults struct {
	ContentSecurityPolicy struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data   map[string][]string
			Http   bool
			Meta   bool
			Policy ObsPolicy
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
			Data     map[string]ObsCookie
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
func invokeObservatoryAnalyzation(host string) (ObsAnalyzeResult, error) {
	apiURL := "https://http-observatory.security.mozilla.org/api/v1/analyze?host=" + host
	var analyzeResult ObsAnalyzeResult

	if logLevel >= logInfo {
		log.Printf("[INFO] Getting observatory analyzation: %v", host)
	}

	// Initiate the scan request, the body of the request contains information to hide the scan from the front-page
	_, err := http.Post(apiURL, "application/x-www-form-urlencoded", strings.NewReader("hidden=true&rescan=false"))
	if err != nil {
		if logLevel >= logError {
			log.Printf("[ERROR] Error invoking observatory API for %v : %v", host, err)
		}
		return ObsAnalyzeResult{}, err
	}

	// Poll every 5 seconds until scan is done, aborting on abnormal or failed states
	for {
		response, err := http.Get(apiURL)
		if err != nil {
			if logLevel >= logError {
				log.Printf("[ERROR] Error polling observatory API for %v : %v", host, err)
			}
			return ObsAnalyzeResult{}, err
		}
		defer response.Body.Close()
		analyzeBody, err := ioutil.ReadAll(response.Body)
		err = json.Unmarshal(analyzeBody, &analyzeResult)

		if err != nil {
			if logLevel >= logError {
				log.Printf("[ERROR] Error unmarshalling: %v", err)
			}
		}
		if logLevel >= logDebug {
			log.Printf("[DEBUG] Observatory Scan is currently %v for host: %v", analyzeResult.State, host)
		}
		switch analyzeResult.State {
		case "FINISHED":
			return analyzeResult, nil
		case "ABORTED":
			observatoryStateError := errors.New("Observatory scan aborted for technical reasons at observatory API")
			if logLevel >= logError {
				log.Printf("[ERROR] Observatory scan failed for host %v", host)
			}
			return ObsAnalyzeResult{}, observatoryStateError
		case "FAILED":
			observatoryStateError := errors.New("Failed to request observatory scan")
			if logLevel >= logError {
				log.Printf("[ERROR] Observatory scan failed for host %v", host)
			}
			return ObsAnalyzeResult{}, observatoryStateError
		case "PENDING", "RUNNING", "STARTING":
			time.Sleep(5 * time.Second)
			continue
		default:
			observatoryStateError := errors.New("Could not request observatory scan")
			if logLevel >= logError {
				log.Printf("[ERROR] Error getting Observatory state for host %v", host)
			}
			return ObsAnalyzeResult{}, observatoryStateError
		}
	}
}

// InvokeObservatoryResults gets the results of an already done scan and
// And adds them to the calling LabsReport object
func invokeObservatoryResults(analyzeResults ObsAnalyzeResult) (ObsScanResults, error) {
	var scanResults ObsScanResults
	// Getting the results of an unfinished scan won't work -- abort
	if analyzeResults.State != "FINISHED" {
		if logLevel >= logError {
			log.Printf("[ERROR] Analysis not finished but tried to get results")
		}
		return ObsScanResults{}, errors.New("Invoked results without finished analysis")
	}

	resultApiUrl := "https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan=" + strconv.Itoa(analyzeResults.ScanID)
	response, err := http.Get(resultApiUrl)
	if err != nil {
		if logLevel >= logError {
			log.Printf("[ERROR] Error invoking observatory API for current host: %v", err)
		}
		return ObsScanResults{}, err
	}
	resultsBody, err := ioutil.ReadAll(response.Body)
	// Since we're getting a JSON as a response, unmarshal it into a new ObservatoryScanResults object
	// And add it to our calling LabsReport-Object
	json.Unmarshal(resultsBody, &scanResults)
	return scanResults, nil
}

func (manager *Manager) obsHandleScan(domains []DomainsReachable, internalChannel chan internalMessage) []DomainsReachable {
	for len(domains) > 0 && int(manager.status.getCurrentScans()) < manager.maxParallelScans {
		manager.firstScan = true
		// pop fist domain
		scan, retDom := domains[0], domains[1:]
		scanMsg := internalMessage{scan, nil, 0, internalNew}
		go manager.obsAssessment(scanMsg, internalChannel)
		manager.status.addCurrentScans(1)
		return retDom
	}
	return domains
}

func parseCSP(policy ObsPolicy) uint16 {
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

func parseObsResult(obsResult ObsScanResults, obsAnaly ObsAnalyzeResult) ObsTableRow {
	var row ObsTableRow

	row.Grade = truncate(obsAnaly.Grade, 2)
	row.Score = obsAnaly.Score

	row.TestsFailed = obsAnaly.TestsFailed
	row.TestsPassed = obsAnaly.TestsPassed
	row.TestsQuantity = obsAnaly.TestsQuantity

	row.CSPPassed = obsResult.ContentSecurityPolicy.Pass
	row.CSPEval = parseCSP(obsResult.ContentSecurityPolicy.Output.Policy)
	row.CSPDesc = truncate(obsResult.ContentSecurityPolicy.ScoreDescription, 250)
	row.CSPResult = truncate(obsResult.ContentSecurityPolicy.Result, 100)

	row.CookiesPassed = obsResult.Cookies.Pass
	row.CookiesDesc = truncate(obsResult.Cookies.ScoreDescription, 250)
	row.CookiesResult = truncate(obsResult.Cookies.Result, 100)

	row.CORSPassed = obsResult.CrossOriginResourceSharing.Pass
	row.CORSDesc = truncate(obsResult.CrossOriginResourceSharing.ScoreDescription, 250)
	row.CORSResult = truncate(obsResult.CrossOriginResourceSharing.Result, 100)

	row.HPKPPassed = obsResult.PublicKeyPinning.Pass
	row.HPKPDesc = truncate(obsResult.PublicKeyPinning.ScoreDescription, 250)
	row.HPKPResult = truncate(obsResult.PublicKeyPinning.Result, 100)

	row.RedirectionPassed = obsResult.Redirection.Pass
	row.RedirectionDesc = truncate(obsResult.Redirection.ScoreDescription, 250)
	row.RedirectionResult = truncate(obsResult.Redirection.Result, 100)

	row.HSTSPassed = obsResult.StrictTransportSecurity.Pass
	row.HSTSDesc = truncate(obsResult.StrictTransportSecurity.ScoreDescription, 250)
	row.HSTSResult = truncate(obsResult.StrictTransportSecurity.Result, 100)

	row.SRIPassed = obsResult.SubresourceIntegrity.Pass
	row.SRIDesc = truncate(obsResult.SubresourceIntegrity.ScoreDescription, 250)
	row.SRIResult = truncate(obsResult.SubresourceIntegrity.Result, 100)

	row.XContentTypePassed = obsResult.XContentTypeOptions.Pass
	row.XContentTypeDesc = truncate(obsResult.XContentTypeOptions.ScoreDescription, 250)
	row.XContentTypeResult = truncate(obsResult.XContentTypeOptions.Result, 100)

	row.XFrameOptionsPassed = obsResult.XFrameOptions.Pass
	row.XFrameOptionsDesc = truncate(obsResult.XFrameOptions.ScoreDescription, 250)
	row.XFrameOptionsResult = truncate(obsResult.XFrameOptions.Result, 100)

	row.XXSSProtectionPassed = obsResult.XXSSProtection.Pass
	row.XXSSProtectionDesc = truncate(obsResult.XXSSProtection.ScoreDescription, 250)
	row.XXSSProtectionResult = truncate(obsResult.XXSSProtection.Result, 100)
	return row
}

func (manager *Manager) obsAssessment(scan internalMessage, internalChannel chan internalMessage) {
	analyze, err := invokeObservatoryAnalyzation(scan.domain.DomainName)
	if err != nil {
		//TODO Handle Error
		log.Printf("Observatory couldn't get Results for %d: %s", scan.domain.DomainID, err.Error())
		scan.results = ObsTableRow{}
		scan.statusCode = internalFatalError
		internalChannel <- scan
		return
	}

	results, err := invokeObservatoryResults(analyze)

	if err != nil {
		//TODO Handle Error
		log.Printf("Observatory couldn't get Results for %d: %s", scan.domain.DomainID, err.Error())
		scan.results = ObsTableRow{}
		scan.statusCode = internalFatalError
		internalChannel <- scan
		return
	}

	row := parseObsResult(results, analyze)

	scan.results = row
	scan.statusCode = internalSuccess
	internalChannel <- scan
}

func (manager *Manager) obsHandleResults(result internalMessage) {
	res, ok := result.results.(ObsTableRow)
	//TODO FIX with error handling
	manager.status.addCurrentScans(-1)

	if !ok {
		//TODO Handle Error

		log.Print("observatory manager couldn't assert type")
		res = ObsTableRow{}
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
		log.Printf("observatory couldn't save results for %s: %s", result.domain.DomainName, err.Error())
		return
	}
}
