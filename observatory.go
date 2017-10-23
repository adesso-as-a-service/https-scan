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
)

var globalObservatory bool

// How many assessment do we have in progress?
var activeObsAssessments = 0

// The maximum number of assessments we can have in progress at any one time.
var maxObsAssessments = 10

// ObservatoryAnalyzeResult is the object to contain the response we get
// From starting an Observatory-Scan
type ObservatoryAnalyzeResult struct {
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
type ObservatoryScanResults struct {
	ContentSecurityPolicy struct {
		Expectation string `json:"expectation"`
		Name        string `json:"name"`
		Output      struct {
			Data interface{} `json:"data"`
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
			Data interface{} `json:"data"`
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

// ToIssueString takes ObservatoryScanResults and iterates over them, returning a string
// That has all issues of the scanned object contained in new lines
func (observatoryResults ObservatoryScanResults) ToIssueString() string {
	var observatoryDescriptions string
	if !observatoryResults.ContentSecurityPolicy.Pass {
		observatoryDescriptions += observatoryResults.ContentSecurityPolicy.ScoreDescription + "\n"
	}
	if !observatoryResults.Cookies.Pass {
		observatoryDescriptions += observatoryResults.Cookies.ScoreDescription + "\n"
	}
	if !observatoryResults.CrossOriginResourceSharing.Pass {
		observatoryDescriptions += observatoryResults.CrossOriginResourceSharing.ScoreDescription + "\n"
	}
	if !observatoryResults.PublicKeyPinning.Pass {
		observatoryDescriptions += observatoryResults.PublicKeyPinning.ScoreDescription + "\n"
	}
	if !observatoryResults.Redirection.Pass {
		observatoryDescriptions += observatoryResults.Redirection.ScoreDescription + "\n"
	}
	if !observatoryResults.StrictTransportSecurity.Pass {
		observatoryDescriptions += observatoryResults.StrictTransportSecurity.ScoreDescription + "\n"
	}
	if !observatoryResults.SubresourceIntegrity.Pass {
		observatoryDescriptions += observatoryResults.SubresourceIntegrity.ScoreDescription + "\n"
	}
	if !observatoryResults.XContentTypeOptions.Pass {
		observatoryDescriptions += observatoryResults.XContentTypeOptions.ScoreDescription + "\n"
	}
	if !observatoryResults.XFrameOptions.Pass {
		observatoryDescriptions += observatoryResults.XFrameOptions.ScoreDescription + "\n"
	}
	if !observatoryResults.XXSSProtection.Pass {
		observatoryDescriptions += observatoryResults.XXSSProtection.ScoreDescription + "\n"
	}
	return observatoryDescriptions
}

// invokeObservatoryAnalyzation starts an HTTP-Observatory assessment and polls
// To see if the scan is done, then adding the result to the calling LabsReport object
func (analyzeResponse *LabsReport) invokeObservatoryAnalyzation(host string) error {
	apiURL := "https://http-observatory.security.mozilla.org/api/v1/analyze?host=" + host
	var analyzeResult ObservatoryAnalyzeResult

	if logLevel >= LOG_INFO {
		log.Printf("[INFO] Getting observatory analyzation: %v", host)
	}

	// Initiate the scan request, the body of the request contains information to hide the scan from the front-page
	_, err := http.Post(apiURL, "application/x-www-form-urlencoded", strings.NewReader("hidden=true&rescan=false"))
	if err != nil {
		if logLevel >= LOG_ERROR {
			log.Printf("[ERROR] Error invoking observatory API for %v : %v", host, err)
		}
		return err
	}

	// Poll every 5 seconds until scan is done, aborting on abnormal or failed states
	for {
		response, err := http.Get(apiURL)
		if err != nil {
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Error polling observatory API for %v : %v", host, err)
			}
			return err
		}
		defer response.Body.Close()
		analyzeBody, err := ioutil.ReadAll(response.Body)
		json.Unmarshal(analyzeBody, &analyzeResult)
		if logLevel >= LOG_DEBUG {
			log.Printf("[DEBUG] Observatory Scan is currently %v for host: %v", analyzeResult.State, host)
		}
		switch analyzeResult.State {
		case "FINISHED":
			analyzeResponse.ObservatoryScan = analyzeResult
			return nil
		case "ABORTED":
			observatoryStateError := errors.New("Observatory scan aborted for technical reasons at observatory API")
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Observatory scan failed for host %v", host)
			}
			analyzeResponse.ObservatoryScan = analyzeResult
			return observatoryStateError
		case "FAILED":
			observatoryStateError := errors.New("Failed to request observatory scan")
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Observatory scan failed for host %v", host)
			}
			analyzeResponse.ObservatoryScan = analyzeResult
			return observatoryStateError
		case "PENDING", "RUNNING", "STARTING":
			time.Sleep(5 * time.Second)
			continue
		default:
			observatoryStateError := errors.New("Could not request observatory scan")
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Error getting Observatory state for host %v", host)
			}
			analyzeResponse.ObservatoryScan = analyzeResult
			return observatoryStateError
		}
	}
}

// InvokeObservatoryResults gets the results of an already done scan and
// And adds them to the calling LabsReport object
func (analyzeResponse *LabsReport) invokeObservatoryResults(analyzeResults ObservatoryAnalyzeResult) error {
	var scanResults ObservatoryScanResults
	// Getting the results of an unfinished scan won't work -- abort
	if analyzeResults.State != "FINISHED" {
		if logLevel >= LOG_ERROR {
			log.Printf("[ERROR] Analysis not finished but tried to get results")
		}
		return errors.New("Invoked results without finished analysis")
	}

	resultApiUrl := "https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan=" + strconv.Itoa(analyzeResults.ScanID)
	response, err := http.Get(resultApiUrl)
	if err != nil {
		if logLevel >= LOG_ERROR {
			log.Printf("[ERROR] Error invoking observatory API for current host: %v", err)
		}
		return err
	}
	resultsBody, err := ioutil.ReadAll(response.Body)
	// Since we're getting a JSON as a response, unmarshel it into a new ObservatoryScanResults object
	// And add it to our calling LabsReport-Object
	json.Unmarshal(resultsBody, &scanResults)
	analyzeResponse.ObservatoryResults = scanResults
	return nil
}

func NewObsAssessment(e Event, eventChannel chan Event) {
	e.senderID = "obs"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	err := e.report.invokeObservatoryAnalyzation(e.host)
	if err != nil {
		if logLevel >= LOG_ERROR {
			log.Printf("[ERROR] Could not invoke mozilla Observatory for host %v: %v", e.report.Host, err)
		}
		e.eventType = INTERNAL_ASSESSMENT_FAILED
		eventChannel <- e
		return
	}
	// If the analyzation was successful (no err) we can get the results now
	if err == nil {
		e.report.invokeObservatoryResults(e.report.ObservatoryScan)
		if err != nil {
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Could not invoke mozilla Observatory results for host %v: %v", e.report.Host, err)
			}
			e.eventType = INTERNAL_ASSESSMENT_FAILED
			eventChannel <- e
			return
		}
	}
	e.eventType = INTERNAL_ASSESSMENT_COMPLETE
	eventChannel <- e
}

func (manager *Manager) startObsAssessment(e Event) {
	go NewObsAssessment(e, manager.InternalEventChannel)
	activeObsAssessments++
}

func (manager *Manager) obsRun() {
	moreObsAssessments := true
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.InternalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {
				activeObsAssessments--
				log.Printf("[ERROR] Observatory Scan for %v failed", e.host)
				//TODO ERROR handeling
				if logLevel >= LOG_NOTICE {
					log.Printf("Obs Active assessments: %v (more: %v)", activeObsAssessments, moreObsAssessments)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_INFO {
					log.Printf("[INFO] Observatory Scan starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_INFO {
					log.Printf("[INFO] Observatory Scan for %v finished", e.host)
				}

				activeObsAssessments--

				if logLevel >= LOG_NOTICE {
					log.Printf("Obs Active assessments: %v (more: %v)", activeObsAssessments, moreObsAssessments)
				}
				e.eventType = FINISHED
				e.senderID = "obs"
				manager.OutputEventChannel <- e

				if logLevel >= LOG_DEBUG {
					log.Printf("[DEBUG] Active assessments: %v (more: %v)", activeObsAssessments, moreObsAssessments)
				}
			}

			// Are we done?
			if (activeObsAssessments == 0) && (moreObsAssessments == false) {
				manager.finish("obs")
				return
			}

			break

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		default:
			<-time.NewTimer(time.Duration(100) * time.Millisecond).C
			if moreObsAssessments {
				if activeObsAssessments < maxObsAssessments {
					e, running := <-manager.InputEventChannel
					if running {
						manager.startObsAssessment(e)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreObsAssessments = false

						if activeObsAssessments == 0 {
							manager.finish("obs")
							return
						}
					}
				}
			}
			break
		}
	}
}
