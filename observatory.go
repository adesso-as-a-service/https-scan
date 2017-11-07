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

// obsTries is the maximum number of scan retries
var obsTries = 2

// activeObsAssessments is the number of active assessments according to the manager
var activeObsAssessments = 0

// maxObsAssessments is the maximal number of active assessments
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
func (analyzeResponse *LabsReport) invokeObservatoryAnalyzation(host string, logger *log.Logger) error {
	apiURL := "https://http-observatory.security.mozilla.org/api/v1/analyze?host=" + host
	var analyzeResult ObservatoryAnalyzeResult

	if logLevel >= LOG_INFO {
		logger.Printf("[INFO] Getting observatory analyzation: %v", host)
	}

	// Initiate the scan request, the body of the request contains information to hide the scan from the front-page
	_, err := http.Post(apiURL, "application/x-www-form-urlencoded", strings.NewReader("hidden=true&rescan=false"))
	if err != nil {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Error invoking observatory API for %v : %v", host, err)
		}
		return err
	}

	// Poll every 5 seconds until scan is done, aborting on abnormal or failed states
	for {
		response, err := http.Get(apiURL)
		if err != nil {
			if logLevel >= LOG_ERROR {
				logger.Printf("[ERROR] Error polling observatory API for %v : %v", host, err)
			}
			return err
		}
		defer response.Body.Close()
		analyzeBody, err := ioutil.ReadAll(response.Body)
		json.Unmarshal(analyzeBody, &analyzeResult)
		if logLevel >= LOG_DEBUG {
			logger.Printf("[DEBUG] Observatory Scan is currently %v for host: %v", analyzeResult.State, host)
		}
		switch analyzeResult.State {
		case "FINISHED":
			analyzeResponse.ObservatoryScan = analyzeResult
			return nil
		case "ABORTED":
			observatoryStateError := errors.New("Observatory scan aborted for technical reasons at observatory API")
			if logLevel >= LOG_ERROR {
				logger.Printf("[ERROR] Observatory scan failed for host %v", host)
			}
			analyzeResponse.ObservatoryScan = analyzeResult
			return observatoryStateError
		case "FAILED":
			observatoryStateError := errors.New("Failed to request observatory scan")
			if logLevel >= LOG_ERROR {
				logger.Printf("[ERROR] Observatory scan failed for host %v", host)
			}
			analyzeResponse.ObservatoryScan = analyzeResult
			return observatoryStateError
		case "PENDING", "RUNNING", "STARTING":
			time.Sleep(5 * time.Second)
			continue
		default:
			observatoryStateError := errors.New("Could not request observatory scan")
			if logLevel >= LOG_ERROR {
				logger.Printf("[ERROR] Error getting Observatory state for host %v", host)
			}
			analyzeResponse.ObservatoryScan = analyzeResult
			return observatoryStateError
		}
	}
}

// InvokeObservatoryResults gets the results of an already done scan and
// And adds them to the calling LabsReport object
func (analyzeResponse *LabsReport) invokeObservatoryResults(analyzeResults ObservatoryAnalyzeResult, logger *log.Logger) error {
	var scanResults ObservatoryScanResults
	// Getting the results of an unfinished scan won't work -- abort
	if analyzeResults.State != "FINISHED" {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Analysis not finished but tried to get results")
		}
		return errors.New("Invoked results without finished analysis")
	}

	resultApiUrl := "https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan=" + strconv.Itoa(analyzeResults.ScanID)
	response, err := http.Get(resultApiUrl)
	if err != nil {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Error invoking observatory API for current host: %v", err)
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

// NewObsAssessment starts the assessment of an event
func NewObsAssessment(e Event, eventChannel chan Event, logger *log.Logger) {
	e.senderID = "obs"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	err := e.report.invokeObservatoryAnalyzation(e.host, logger)
	if err != nil {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Could not invoke mozilla Observatory for host %v: %v", e.report.Host, err)
		}
		e.eventType = INTERNAL_ASSESSMENT_FAILED
		eventChannel <- e
		return
	}
	// If the analyzation was successful (no err) we can get the results now
	if err == nil {
		e.report.invokeObservatoryResults(e.report.ObservatoryScan, logger)
		if err != nil {
			if logLevel >= LOG_ERROR {
				logger.Printf("[ERROR] Could not invoke mozilla Observatory results for host %v: %v", e.report.Host, err)
			}
			e.eventType = INTERNAL_ASSESSMENT_FAILED
			eventChannel <- e
			return
		}
	}
	e.eventType = INTERNAL_ASSESSMENT_COMPLETE
	eventChannel <- e
}

// startObsAssessment calls NewObsAssessments as a new goroutine
func (manager *Manager) startObsAssessment(e Event) {
	go NewObsAssessment(e, manager.InternalEventChannel, manager.logger)
	activeObsAssessments++
}

// obsRun starts the manager responsible for the observatory-scan
func (manager *Manager) obsRun() {
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.InternalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {
				if logLevel >= LOG_NOTICE {
					manager.logger.Printf("Obs Active assessments: %v ", activeObsAssessments)
				}
				activeObsAssessments--
				e.tries++
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Observatory for %v failed for the %v. time", e.host, e.tries)
				}
				if e.tries < obsTries {
					manager.startObsAssessment(e)
				} else {
					e.eventType = ERROR
					if logLevel >= LOG_ERROR {
						manager.logger.Printf("[ERROR] Observatory for %v ultimately failed", e.host)
					}
					manager.ControlEventChannel <- e
				}
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Active assessments: %v", activeObsAssessments)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] Observatory Scan starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] Observatory Scan for %v finished", e.host)
				}

				activeObsAssessments--

				e.eventType = FINISHED
				e.senderID = "obs"
				manager.OutputEventChannel <- e
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Active assessments: %v", activeObsAssessments)
				}

			}
			break
		// if someone asked if there are still active assessments
		case <-manager.CloseChannel:
			manager.CloseChannel <- (activeObsAssessments == 0)
		default:
			<-time.NewTimer(time.Duration(500) * time.Millisecond).C

			if activeObsAssessments < maxObsAssessments {
				select {
				case e := <-manager.InputEventChannel:
					e.tries = 0
					if logLevel >= LOG_DEBUG {
						manager.logger.Println("[DEBUG] New event received")
					}
					manager.startObsAssessment(e)
				case <-time.After(time.Millisecond * 100):
					break
				}
			}

			break
		}
	}
}
