package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// USER_AGENT tells the api which version is used
var USER_AGENT = "ssllabs-scan v1.5.0 (dev $Id$)"

// labsTries is the maximum number of scan retries
var labsTries = 2

// activeLabsAssessments is the number of active assessments according to the manager
var activeLabsAssessments = 0

// currentLabsAssessments is the number of active assessments according to the api
var currentLabsAssessments = -1

// maxLabsAssessments is the maximal number of active assessments the server allows us
var maxLabsAssessments = -1

// globalNewAssessmentCoolOff is the time waited between starting new assessments
var globalNewAssessmentCoolOff int64 = 1100

// requestCounter is the total number of requests send
var requestCounter uint64 = 0

// relative Auslastung von maxAssessments
var faktor = 1.0

var apiLocation = "https://api.ssllabs.com/api/v3"

var httpClient *http.Client

// invokeGetRepeatedly sends command to api and keeps requesting until there are results
// or an error
func invokeGetRepeatedly(url string, logger *log.Logger) (*http.Response, []byte, error) {
	retryCount := 0

	for {
		var reqId = atomic.AddUint64(&requestCounter, 1)

		if logLevel >= LOG_DEBUG {
			logger.Printf("[DEBUG] Request #%v: %v", reqId, url)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Add("User-Agent", USER_AGENT)

		resp, err := httpClient.Do(req)
		if err == nil {
			if logLevel >= LOG_DEBUG {
				logger.Printf("[DEBUG] Response #%v status: %v %v", reqId, resp.Proto, resp.Status)
			}

			if logLevel >= LOG_TRACE {
				for key, values := range resp.Header {
					for _, value := range values {
						logger.Printf("[TRACE] %v: %v\n", key, value)
					}
				}
			}

			if logLevel >= LOG_NOTICE {
				for key, values := range resp.Header {
					if strings.ToLower(key) == "x-message" {
						for _, value := range values {
							logger.Printf("[NOTICE] Server message: %v\n", value)
						}
					}
				}
			}

			// Update current assessments.

			headerValue := resp.Header.Get("X-Current-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if currentLabsAssessments != i {
						currentLabsAssessments = i

						if logLevel >= LOG_NOTICE {
							logger.Printf("[NOTICE] Server set current assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= LOG_WARNING {
						logger.Printf("[WARNING] Ignoring invalid X-Current-Assessments value (%v): %v", headerValue, err)
					}
				}
			}

			// Update maximum assessments.

			headerValue = resp.Header.Get("X-Max-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if maxLabsAssessments != i {
						maxLabsAssessments = i

						if maxLabsAssessments <= 0 {
							logger.Fatalf("[ERROR] Server doesn't allow further API requests")
						}

						if logLevel >= LOG_NOTICE {
							logger.Printf("[NOTICE] Server set maximum assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= LOG_WARNING {
						logger.Printf("[WARNING] Ignoring invalid X-Max-Assessments value (%v): %v", headerValue, err)
					}
				}
			}

			// Retrieve the response body.

			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, nil, err
			}

			if logLevel >= LOG_TRACE {
				logger.Printf("[TRACE] Response #%v body:\n%v", reqId, string(body))
			}

			return resp, body, nil
		} else {
			if strings.Contains(err.Error(), "EOF") {
				// Server closed a persistent connection on us, which
				// Go doesn't seem to be handling well. So we'll try one
				// more time.
				if retryCount > 5 {
					logger.Fatalf("[ERROR] Too many HTTP requests (5) failed with EOF (ref#2)")
				}

				if logLevel >= LOG_DEBUG {
					logger.Printf("[DEBUG] HTTP request failed with EOF (ref#2)")
				}
			} else {
				logger.Fatalf("[ERROR] HTTP request failed: %v (ref#2)", err.Error())
			}

			retryCount++
		}
	}
}

// invokeApi begins the ssllabs-scan defined in command for the api and returns results
func invokeApi(command string, logger *log.Logger) (*http.Response, []byte, error) {
	var url = apiLocation + "/" + command

	for {
		resp, body, err := invokeGetRepeatedly(url, logger)
		if err != nil {
			return nil, nil, err
		}

		// Status codes 429, 503, and 529 essentially mean try later. Thus,
		// if we encounter them, we sleep for a while and try again.
		if resp.StatusCode == 429 {
			return resp, body, errors.New("Assessment failed: 429")
		} else if (resp.StatusCode == 503) || (resp.StatusCode == 529) {
			// In case of the overloaded server, randomize the sleep time so
			// that some clients reconnect earlier and some later.

			sleepTime := 15 + rand.Int31n(15)

			if logLevel >= LOG_NOTICE {
				logger.Printf("[NOTICE] Sleeping for %v minutes after a %v response", sleepTime, resp.StatusCode)
			}

			time.Sleep(time.Duration(sleepTime) * time.Minute)
		} else if (resp.StatusCode != 200) && (resp.StatusCode != 400) {
			logger.Fatalf("[ERROR] Unexpected response status code %v", resp.StatusCode)
		} else {
			return resp, body, nil
		}
	}
}

// invokeInfo gets infos (maxAssessments etc) from api
func invokeInfo(logger *log.Logger) (*LabsInfo, error) {
	var command = "info"

	_, body, err := invokeApi(command, logger)
	if err != nil {
		return nil, err
	}

	var labsInfo LabsInfo
	err = json.Unmarshal(body, &labsInfo)
	if err != nil {
		logger.Printf("[ERROR] JSON unmarshal error: %v", err)
		return nil, err
	}

	return &labsInfo, nil
}

// invokeAnalyze builds the request command for the api and sends it to the api via invokeApi
func invokeAnalyze(host string, startNew bool, fromCache bool, logger *log.Logger) (*LabsReport, error) {
	var command = "analyze?host=" + host + "&all=done"

	if fromCache {
		command = command + "&fromCache=on"

		if globalMaxAge != 0 {
			command = command + "&maxAge=" + strconv.Itoa(globalMaxAge)
		}
	} else if startNew {
		command = command + "&startNew=on"
	}

	if globalIgnoreMismatch {
		command = command + "&ignoreMismatch=on"
	}

	resp, body, err := invokeApi(command, logger)
	if err != nil {
		return nil, err
	}

	// Use the status code to determine if the response is an error.
	if resp.StatusCode == 400 {
		// Parameter validation error.

		var apiError LabsErrorResponse
		err = json.Unmarshal(body, &apiError)
		if err != nil {
			logger.Printf("[ERROR] JSON unmarshal error: %v", err)
			return nil, err
		}

		return nil, apiError
	} else {
		// We should have a proper response.

		var analyzeResponse LabsReport
		err = json.Unmarshal(body, &analyzeResponse)
		if err != nil {
			logger.Printf("[ERROR] JSON unmarshal error: %v", err)
			return nil, err
		}

		// Add the JSON body to the response
		analyzeResponse.rawJSON = string(body)
		return &analyzeResponse, nil
	}
}

// NewLabsAssessment starts the ssllabs-assessment of an event and communicates it
// to the manager
func NewLabsAssessment(e Event, eventChannel chan Event, logger *log.Logger) {
	e.senderID = "labs"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	var report *LabsReport
	var startTime int64 = -1
	var startNew = globalStartNew

	for {
		myResponse, err := invokeAnalyze(e.host, startNew, globalFromCache, logger)
		if err != nil {
			if strings.Contains(err.Error(), "429") {
				e.eventType = 429
				eventChannel <- e
				return
			}
			e.eventType = INTERNAL_ASSESSMENT_FAILED
			eventChannel <- e
			return
		}

		if startTime == -1 {
			startTime = myResponse.StartTime
			startNew = false
		} else {
			// Abort this assessment if the time we receive in a follow-up check
			// is older than the time we got when we started the request. The
			// upstream code should then retry the hostname in order to get
			// consistent results.
			if myResponse.StartTime > startTime {
				e.eventType = INTERNAL_ASSESSMENT_FAILED
				logger.Println("startTime diffrence")
				eventChannel <- e
				return
			} else {
				startTime = myResponse.StartTime
			}
		}

		if (myResponse.Status == "READY") || (myResponse.Status == "ERROR") {
			report = myResponse
			break
		}

		time.Sleep(5 * time.Second)
	}
	e.report = report
	e.eventType = INTERNAL_ASSESSMENT_COMPLETE
	eventChannel <- e
}

// startLabsAssessments starts every assessment as a goroutine
func (manager *Manager) startLabsAssessment(e Event) {
	go NewLabsAssessment(e, manager.internalEventChannel, manager.logger)
	activeLabsAssessments++
}

// labsRun starts the manager responsible for the ssllabs-scan
func (manager *Manager) labsRun() {
	if logLevel >= LOG_NOTICE {
		manager.logger.Println("[NOTICE] SSLLabs-Manager started")
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: globalInsecure},
		DisableKeepAlives: false,
		Proxy:             http.ProxyFromEnvironment,
	}

	httpClient = &http.Client{Transport: transport}

	// Ping SSL Labs to determine how many concurrent
	// assessments we're allowed to use. Print the API version
	// information and the limits.

	labsInfo, err := invokeInfo(manager.logger)
	if err != nil {
		// TODO Signal error so that we return the correct exit code
	}

	if logLevel >= LOG_INFO {
		manager.logger.Printf("[INFO] SSL Labs v%v (criteria version %v)", labsInfo.EngineVersion, labsInfo.CriteriaVersion)
	}

	if logLevel >= LOG_INFO {
		for _, message := range labsInfo.Messages {
			manager.logger.Printf("[INFO] Server message: %v", message)
		}
	}

	maxLabsAssessments = labsInfo.MaxAssessments

	if maxLabsAssessments <= 0 {
		if logLevel >= LOG_WARNING {
			manager.logger.Printf("[WARNING] You're not allowed to request new assessments")
		}
	}

	if labsInfo.NewAssessmentCoolOff >= 1000 {
		globalNewAssessmentCoolOff = 100 + labsInfo.NewAssessmentCoolOff
	} else {
		if logLevel >= LOG_WARNING {
			manager.logger.Printf("[WARNING] Info.NewAssessmentCoolOff too small: %v", labsInfo.NewAssessmentCoolOff)
		}
	}

	coolOff := time.NewTimer(time.Duration(globalNewAssessmentCoolOff) * time.Millisecond)
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.internalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {

				activeLabsAssessments--
				e.tries++
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] SSLLabs-Assessment for %v failed for the %v. time", e.host, e.tries)
				}
				if e.tries < labsTries {
					// retry this event
					manager.startLabsAssessment(e)
				} else {
					// event failed
					e.eventType = ERROR
					if logLevel >= LOG_ERROR {
						manager.logger.Printf("[ERROR] SSLLabs-Assessment for %v ultimately failed", e.host)
					}
					manager.ControlEventChannel <- e
				}
			}

			if e.eventType == 429 {
				// Error 429 occurred. Retry this later
				activeLabsAssessments--
				e.eventType = REERROR
				if logLevel >= LOG_ERROR {
					manager.logger.Printf("[ERROR] SSLLabs-Assessment 429 Error for %v", e.host)
				}
				manager.ControlEventChannel <- e
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				// Assessment started
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Assessment starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				// assessment complete, so this is https reachable
				e.report.Reachable = "https"
				if logLevel >= LOG_DEBUG {
					msg := ""

					if len(e.report.Endpoints) == 0 {
						msg = fmt.Sprintf("[WARN] Assessment failed: %v (%v)", e.host, e.report.StatusMessage)
					} else if len(e.report.Endpoints) > 1 {
						msg = fmt.Sprintf("[DEBUG] Assessment complete: %v (%v hosts in %v seconds)",
							e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
					} else {
						msg = fmt.Sprintf("[DEBUG] Assessment complete: %v (%v host in %v seconds)",
							e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
					}

					for _, endpoint := range e.report.Endpoints {
						if endpoint.Grade != "" {
							msg = msg + "\n    " + endpoint.IpAddress + ": " + endpoint.Grade
						} else {
							msg = msg + "\n    " + endpoint.IpAddress + ": Err: " + endpoint.StatusMessage
						}
					}

					manager.logger.Println(msg)
				}
				activeLabsAssessments--

				// We have a finished assessment now that we can add third-party information to
				// And we won't re-query these third partys by relying on the ssllabs-scan polling

				e.eventType = FINISHED
				e.senderID = "labs"

				manager.OutputEventChannel <- e

				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Active assessments: %v", activeLabsAssessments)
				}
			}

			break
		// if someone asked if there are still active assessments
		case <-manager.CloseChannel:
			if logLevel >= LOG_DEBUG {
				manager.logger.Println("[DEBUG] Close Question received!")
			}

			manager.CloseChannel <- (activeLabsAssessments == 0)

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		case <-coolOff.C:

			if currentLabsAssessments < int(faktor*float64(maxLabsAssessments))+1 && activeLabsAssessments < int(faktor*float64(maxLabsAssessments))+1 {
				select {
				case e := <-manager.InputEventChannel:
					e.tries = 0
					if logLevel >= LOG_DEBUG {
						manager.logger.Println("[DEBUG] New event received")
					}
					manager.startLabsAssessment(e)
				case <-time.After(time.Millisecond * 100):
					if logLevel >= LOG_DEBUG {
						manager.logger.Printf("[DEBUG] No new event received, currently %v active assessments", activeLabsAssessments)
					}

					break
				}
			}
			coolOff = time.NewTimer(time.Duration(globalNewAssessmentCoolOff) * time.Millisecond)
			break
		}
	}
}
