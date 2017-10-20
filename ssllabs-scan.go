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

var USER_AGENT = "ssllabs-scan v1.4.0 (stable $Id$)"

// How many assessment do we have in progress?
var activeLabsAssessments = 0

// How many assessments does the server think we have in progress?
var currentLabsAssessments = -1

// The maximum number of assessments we can have in progress at any one time.
var maxLabsAssessments = -1

var requestCounter uint64 = 0

var apiLocation = "https://api.ssllabs.com/api/v2"

var httpClient *http.Client

const (
	INTERNAL_ASSESSMENT_FAILED   = -1
	INTERNAL_ASSESSMENT_STARTING = 0
	INTERNAL_ASSESSMENT_COMPLETE = 1
)

func invokeGetRepeatedly(url string) (*http.Response, []byte, error) {
	retryCount := 0

	for {
		var reqId = atomic.AddUint64(&requestCounter, 1)

		if logLevel >= LOG_DEBUG {
			log.Printf("[DEBUG] Request #%v: %v", reqId, url)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Add("User-Agent", USER_AGENT)

		resp, err := httpClient.Do(req)
		if err == nil {
			if logLevel >= LOG_DEBUG {
				log.Printf("[DEBUG] Response #%v status: %v %v", reqId, resp.Proto, resp.Status)
			}

			if logLevel >= LOG_TRACE {
				for key, values := range resp.Header {
					for _, value := range values {
						log.Printf("[TRACE] %v: %v\n", key, value)
					}
				}
			}

			if logLevel >= LOG_NOTICE {
				for key, values := range resp.Header {
					if strings.ToLower(key) == "x-message" {
						for _, value := range values {
							log.Printf("[NOTICE] Server message: %v\n", value)
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

						if logLevel >= LOG_DEBUG {
							log.Printf("[DEBUG] Server set current assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= LOG_WARNING {
						log.Printf("[WARNING] Ignoring invalid X-Current-Assessments value (%v): %v", headerValue, err)
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
							log.Fatalf("[ERROR] Server doesn't allow further API requests")
						}

						if logLevel >= LOG_DEBUG {
							log.Printf("[DEBUG] Server set maximum assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= LOG_WARNING {
						log.Printf("[WARNING] Ignoring invalid X-Max-Assessments value (%v): %v", headerValue, err)
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
				log.Printf("[TRACE] Response #%v body:\n%v", reqId, string(body))
			}

			return resp, body, nil
		} else {
			if strings.Contains(err.Error(), "EOF") {
				// Server closed a persistent connection on us, which
				// Go doesn't seem to be handling well. So we'll try one
				// more time.
				if retryCount > 5 {
					log.Fatalf("[ERROR] Too many HTTP requests (5) failed with EOF (ref#2)")
				}

				if logLevel >= LOG_DEBUG {
					log.Printf("[DEBUG] HTTP request failed with EOF (ref#2)")
				}
			} else {
				log.Fatalf("[ERROR] HTTP request failed: %v (ref#2)", err.Error())
			}

			retryCount++
		}
	}
}

func invokeApi(command string) (*http.Response, []byte, error) {
	var url = apiLocation + "/" + command

	for {
		resp, body, err := invokeGetRepeatedly(url)
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
				log.Printf("[NOTICE] Sleeping for %v minutes after a %v response", sleepTime, resp.StatusCode)
			}

			time.Sleep(time.Duration(sleepTime) * time.Minute)
		} else if (resp.StatusCode != 200) && (resp.StatusCode != 400) {
			log.Fatalf("[ERROR] Unexpected response status code %v", resp.StatusCode)
		} else {
			return resp, body, nil
		}
	}
}

func invokeInfo() (*LabsInfo, error) {
	var command = "info"

	_, body, err := invokeApi(command)
	if err != nil {
		return nil, err
	}

	var labsInfo LabsInfo
	err = json.Unmarshal(body, &labsInfo)
	if err != nil {
		log.Printf("[ERROR] JSON unmarshal error: %v", err)
		return nil, err
	}

	return &labsInfo, nil
}

func invokeAnalyze(host string, startNew bool, fromCache bool) (*LabsReport, error) {
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

	resp, body, err := invokeApi(command)
	if err != nil {
		return nil, err
	}

	// Use the status code to determine if the response is an error.
	if resp.StatusCode == 400 {
		// Parameter validation error.

		var apiError LabsErrorResponse
		err = json.Unmarshal(body, &apiError)
		if err != nil {
			log.Printf("[ERROR] JSON unmarshal error: %v", err)
			return nil, err
		}

		return nil, apiError
	} else {
		// We should have a proper response.

		var analyzeResponse LabsReport
		err = json.Unmarshal(body, &analyzeResponse)
		if err != nil {
			log.Printf("[ERROR] JSON unmarshal error: %v", err)
			return nil, err
		}

		// Add the JSON body to the response
		analyzeResponse.rawJSON = string(body)

		return &analyzeResponse, nil
	}
}

func NewLabsAssessment(e Event, eventChannel chan Event) {
	e.senderID = "labs"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	var report *LabsReport
	var startTime int64 = -1
	var startNew = globalStartNew

	for {
		myResponse, err := invokeAnalyze(e.host, startNew, globalFromCache)
		if err != nil {
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

func (manager *Manager) startLabsAssessment(e Event) {
	go NewLabsAssessment(e, manager.InternalEventChannel)
	activeLabsAssessments++
}

func (manager *Manager) labsRun() {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: globalInsecure},
		DisableKeepAlives: false,
		Proxy:             http.ProxyFromEnvironment,
	}

	httpClient = &http.Client{Transport: transport}

	// Ping SSL Labs to determine how many concurrent
	// assessments we're allowed to use. Print the API version
	// information and the limits.

	labsInfo, err := invokeInfo()
	if err != nil {
		// TODO Signal error so that we return the correct exit code
	}

	if logLevel >= LOG_INFO {
		log.Printf("[INFO] SSL Labs v%v (criteria version %v)", labsInfo.EngineVersion, labsInfo.CriteriaVersion)
	}

	if logLevel >= LOG_NOTICE {
		for _, message := range labsInfo.Messages {
			log.Printf("[NOTICE] Server message: %v", message)
		}
	}

	maxLabsAssessments = labsInfo.MaxAssessments

	if maxLabsAssessments <= 0 {
		if logLevel >= LOG_WARNING {
			log.Printf("[WARNING] You're not allowed to request new assessments")
		}
	}

	moreLabsAssessments := true

	if labsInfo.NewAssessmentCoolOff >= 1000 {
		globalNewAssessmentCoolOff = 100 + labsInfo.NewAssessmentCoolOff
	} else {
		if logLevel >= LOG_WARNING {
			log.Printf("[WARNING] Info.NewAssessmentCoolOff too small: %v", labsInfo.NewAssessmentCoolOff)
		}
	}

	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.InternalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {
				activeLabsAssessments--
				log.Printf("[ERROR] ssllabs-scan for %v failed!", e.host)
				//TODO ERROR handeling
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_INFO {
					log.Printf("[INFO] Assessment starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_INFO {
					msg := ""

					if len(e.report.Endpoints) == 0 {
						msg = fmt.Sprintf("[WARN] Assessment failed: %v (%v)", e.host, e.report.StatusMessage)
					} else if len(e.report.Endpoints) > 1 {
						msg = fmt.Sprintf("[INFO] Assessment complete: %v (%v hosts in %v seconds)",
							e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
					} else {
						msg = fmt.Sprintf("[INFO] Assessment complete: %v (%v host in %v seconds)",
							e.host, len(e.report.Endpoints), (e.report.TestTime-e.report.StartTime)/1000)
					}

					for _, endpoint := range e.report.Endpoints {
						if endpoint.Grade != "" {
							msg = msg + "\n    " + endpoint.IpAddress + ": " + endpoint.Grade
						} else {
							msg = msg + "\n    " + endpoint.IpAddress + ": Err: " + endpoint.StatusMessage
						}
					}

					log.Println(msg)
				}

				activeLabsAssessments--

				// We have a finished assessment now that we can add third-party information to
				// And we won't re-query these third partys by relying on the ssllabs-scan polling

				e.eventType = FINISHED
				e.senderID = "labs"

				manager.OutputEventChannel <- e

				if logLevel >= LOG_DEBUG {
					log.Printf("[DEBUG] Active assessments: %v (more: %v)", activeLabsAssessments, moreLabsAssessments)
				}
			}

			// Are we done?
			if (activeLabsAssessments == 0) && (moreLabsAssessments == false) {
				manager.finish("labs")
				return
			}

			break

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		default:
			<-time.NewTimer(time.Duration(globalNewAssessmentCoolOff) * time.Millisecond).C

			if moreLabsAssessments {
				if currentLabsAssessments < maxLabsAssessments {
					e, running := <-manager.InputEventChannel
					if running {
						manager.startLabsAssessment(e)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreLabsAssessments = false

						if activeLabsAssessments == 0 {
							manager.finish("labs")
							return
						}
					}
				}
			}
			break
		}
	}
}
