package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// secHTries is the maximum number of scan retries
var secHTries = 3

// activeSecHAssessments is the number of active assessments according to the manager
var activeSecHAssessments = 0

// maxSecHAssessments is the maximal number of active assessments
var maxSecHAssessments = 10

// Securityheaders is the object used for unmarshalling the results by the API
type Securityheaders struct {
	Score                   string
	XFrameOptions           string
	StrictTransportSecurity string
	XContentTypeOptions     string
	XXSSProtection          string
	ContentSecurityPolicy   string
	ReferrerPolicy          string
}

// parseResponse extracts the results of the securityheaders-scan out of the request response
func parseResponse(r io.Reader) *Securityheaders {
	z := html.NewTokenizer(r)
	var secH Securityheaders
	isRaw := false
	isMissing := false

	for {
		tt := z.Next()
		switch {
		case tt == html.ErrorToken:
			return &secH
		case tt == html.EndTagToken:
			t := z.Token()
			if t.Data == "table" {
				if isRaw {
					isRaw = false
				}
				if isMissing {
					isMissing = false
				}
			}
		case tt == html.StartTagToken:
			t := z.Token()
			switch {
			case t.Data == "div":
				hh := z.Next()
				if hh == html.TextToken {
					h := z.Token()
					switch h.Data {
					// we are in the Raw Headers now
					case "Raw Headers":
						isRaw = true
						break
					// we are in the missing headers now
					case "Missing Headers":
						isRaw = false
						isMissing = true
						break
					}

				}
			case t.Data == "th":
				hh := z.Next()
				if hh == html.TextToken {
					h := z.Token()
					switch h.Data {
					// save Results according to the current section
					case "X-Frame-Options":
						if isMissing {
							secH.XFrameOptions = "missing"
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XFrameOptions = h.Data
						}

					case "Strict-Transport-Security":
						if isMissing {
							secH.StrictTransportSecurity = "missing"
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.StrictTransportSecurity = h.Data
						}

					case "X-Content-Type-Options":
						if isMissing {
							secH.XContentTypeOptions = "missing"
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XContentTypeOptions = h.Data
						}

					case "X-XSS-Protection":
						if isMissing {
							secH.XXSSProtection = "missing"
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.XXSSProtection = h.Data
						}

					case "Content-Security-Policy":
						if isMissing {
							secH.ContentSecurityPolicy = "missing"
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.ContentSecurityPolicy = h.Data
						}

					case "Referrer-Policy":
						if isMissing {
							secH.ReferrerPolicy = "missing"
							break
						}
						if isRaw {
							for hh = z.Next(); hh != html.TextToken; hh = z.Next() {
							}
							h := z.Token()
							secH.ReferrerPolicy = h.Data
						}

					}
				}

			}

		}
	}

}

// invokeSecurityHeaders is called by a LabsReport object to query the securityheaders.io
// API for grading and adds the result to the object
func (analyzeResponse *LabsReport) invokeSecurityHeaders(host string, supportsSSL bool, logger *log.Logger) error {
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
	response, err := http.Get(apiURL)
	if err != nil {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] Error contacting securityheaders.io with host %v : %v", host, err)
		}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if logLevel >= LOG_ERROR {
			logger.Printf("[ERROR] securityheaders.io returned non-200 status for host %v : %v", host, response.Status)
		}
		err = errors.New("security Header Assessment failed")
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
	//Parse the Results
	securityheaders := parseResponse(response.Body)

	// Unmarshal the json object and set the grade and security-header configuration
	// Of the object we've been working on
	json.Unmarshal(xScore, &securityheaders)
	if securityheaders.Score == "" {
		if supportsSSL {
			return errors.New("Retry this")
		} else {
			return errors.New("Securityheader.io could not deliver a result")
		}

	}
	analyzeResponse.HeaderScore = *securityheaders
	return nil
}

// NewSecHAssessment starts the securityheaders assessment of an event
func NewSecHAssessment(e Event, eventChannel chan Event, logger *log.Logger) {
	e.senderID = "secH"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	err := e.report.invokeSecurityHeaders(e.host, e.https, logger)
	if err != nil {
		//If securityheaders is unreachable for https try again
		if strings.Contains(err.Error(), "Retry") {
			if logLevel >= LOG_NOTICE {
				logger.Printf("[NOTICE] Retrying securityheaders-scan without https for %v", e.host)

			}
			err := e.report.invokeSecurityHeaders(e.host, false, logger)
			if err == nil {
				e.eventType = INTERNAL_ASSESSMENT_COMPLETE
				eventChannel <- e
				return
			}
		}
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

// startSecHAssessment calls NewSecHAssessments as a new goroutine
func (manager *Manager) startSecHAssessment(e Event) {
	go NewSecHAssessment(e, manager.internalEventChannel, manager.logger)
	activeSecHAssessments++
}

// secHRun starts the manager responsible for the securityheaders-scan
func (manager *Manager) secHRun() {
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.internalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {
				activeSecHAssessments--
				e.tries++
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] SecHead-Scan for %v failed for the %v. time", e.host, e.tries)
				}
				if e.tries < secHTries {
					manager.startSecHAssessment(e)
				} else {
					e.eventType = ERROR
					if logLevel >= LOG_ERROR {
						manager.logger.Printf("[ERROR] SecHead-Scan for %v ultimately failed", e.host)
					}
					manager.ControlEventChannel <- e
				}
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Active assessments: %v", activeSecHAssessments)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] SecHead-Scan starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] SecHead-Scan for %v finished", e.host)
				}

				activeSecHAssessments--

				e.eventType = FINISHED
				e.senderID = "secH"
				manager.OutputEventChannel <- e
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Active assessments: %v", activeSecHAssessments)
				}
			}
			break
		// if someone asked if there are still active assessments
		case <-manager.CloseChannel:
			manager.CloseChannel <- (activeSecHAssessments == 0)
		default:
			<-time.NewTimer(time.Duration(100) * time.Millisecond).C

			if activeSecHAssessments < maxSecHAssessments {
				select {
				case e := <-manager.InputEventChannel:
					e.tries = 0
					if logLevel >= LOG_DEBUG {
						manager.logger.Println("[DEBUG] New event received")
					}
					manager.startSecHAssessment(e)
				case <-time.After(time.Millisecond * 500):
					break
				}
			}

			break
		}
	}
}
