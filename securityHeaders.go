package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

var globalSecurityheaders bool

//How often do we try
var secHTries = 2

// How many assessment do we have in progress?
var activeSecHAssessments = 0

// The maximum number of assessments we can have in progress at any one time.
var maxSecHAssessments = 10

// Securityheaders is the object used for unmarshalling the results by the API
type Securityheaders struct {
	Score                   string
	Colour                  string
	XFrameOptions           string
	StrictTransportSecurity string
	XContentTypeOptions     string
	XXSSProtection          string
}

// invokeSecurityHeaders is called by a LabsReport object to query the securityheaders.io
// API for grading and adds the result to the object
func (analyzeResponse *LabsReport) invokeSecurityHeaders(host string, supportsSSL bool, logger *log.Logger) error {
	var securityheaders Securityheaders
	var apiURL string
	var hostURL string

	if supportsSSL {
		hostURL = "https://" + host
		apiURL = "https://securityheaders.io/?q=" + hostURL + "&hide=on&followRedirects=on"
	} else {
		hostURL = "http://" + host
		apiURL = "https://securityheaders.io/?q=" + hostURL + "&hide=on&followRedirects=on"
	}

	if logLevel >= LOG_INFO {
		logger.Printf("[INFO] Getting securityheaders.io assessment: %v", host)
	}

	// Get http Header from the securityheaders API to get the grading of the scanned host
	response, err := http.Head(apiURL)
	if err != nil {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Error contacting securityheaders.io with host %v : %v", host, err)
		}
	}
	if response.StatusCode != http.StatusOK {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] securityheaders.io returned non-200 status for host %v : %v", host, response.Status)
		}
		err = errors.New("Security Header Assessment failed.")
		return err
	}

	// Disable security checks to get information even if cert is bad
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	//Get the HTTP head of the host directly to get the security headers and their configuration
	headerResponse, err := client.Head(hostURL)
	if err != nil {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Error getting headers of host %v : %v", host, err)
		}
		return err
	}
	if response.StatusCode != http.StatusOK {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] host returned non-200 status when getting headers %v : %v", host, response.Status)
		}
		err = errors.New("Security Header Assessment failed.")
		return err
	}

	// The grading done by securityheaders.io is Base64-encoded, so we decode it and get a JSON object
	xScore, err := base64.StdEncoding.DecodeString(response.Header.Get("X-Score"))
	if err != nil {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Error decoding X-Score Header from securityheaders.io for %v", host)
		}
		return err
	}

	// Unmarshal the json object and set the grade and security-header configuration
	// Of the object we've been working on
	json.Unmarshal(xScore, &securityheaders)
	securityheaders.StrictTransportSecurity = headerResponse.Header.Get("Strict-Transport-Security")
	securityheaders.XContentTypeOptions = headerResponse.Header.Get("X-Content-Type-Options")
	securityheaders.XFrameOptions = headerResponse.Header.Get("X-Frame-Options")
	securityheaders.XXSSProtection = headerResponse.Header.Get("X-XSS-Protection")
	analyzeResponse.HeaderScore = securityheaders
	return nil
}

func NewSecHAssessment(e Event, eventChannel chan Event, logger *log.Logger) {
	e.senderID = "secH"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	err := e.report.invokeSecurityHeaders(e.report.Host, true, logger)
	if err != nil {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Could not invoke security headers for host %v: %v", e.report.Host, err)

		}
		e.eventType = INTERNAL_ASSESSMENT_FAILED
		eventChannel <- e
		return
	}
	e.eventType = INTERNAL_ASSESSMENT_COMPLETE
	eventChannel <- e
}

func (manager *Manager) startSecHAssessment(e Event) {
	go NewSecHAssessment(e, manager.InternalEventChannel, manager.logger)
	activeSecHAssessments++
}

func (manager *Manager) secHRun() {
	moreSecHAssessments := true
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.InternalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {
				activeSecHAssessments--
				manager.logger.Printf("[ERROR] Securityheader Scan for %v failed", e.host)
				if logLevel >= LOG_NOTICE {
					manager.logger.Printf("SecH Active assessments: %v (more: %v)", activeSecHAssessments, moreSecHAssessments)
				}
				e.tries++
				if e.tries < secHTries {
					manager.startSecHAssessment(e)
				} else {
					e.eventType = ERROR
					manager.ControlEventChannel <- e
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Securityheader Scan starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Securityheader Scan for %v finished", e.host)
				}

				activeSecHAssessments--

				if logLevel >= LOG_NOTICE {
					manager.logger.Printf("SecH Active assessments: %v (more: %v)", activeSecHAssessments, moreSecHAssessments)
				}
				e.eventType = FINISHED
				e.senderID = "secH"
				manager.OutputEventChannel <- e

				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] Active assessments: %v (more: %v)", activeSecHAssessments, moreSecHAssessments)
				}
			}

			// Are we done?
			if (activeSecHAssessments == 0) && (moreSecHAssessments == false) {
				manager.finish("secH")
				return
			}

			break

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		default:
			<-time.NewTimer(time.Duration(100) * time.Millisecond).C

			if moreSecHAssessments {
				if activeSecHAssessments < maxSecHAssessments {
					e, running := <-manager.InputEventChannel
					if running {
						e.tries = 0
						manager.startSecHAssessment(e)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreSecHAssessments = false

						if activeSecHAssessments == 0 {
							manager.finish("secH")
							return
						}
					}
				}
			}
			break
		}
	}
}
