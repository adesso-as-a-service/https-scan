package main

import (
	"crypto/tls"
	"log"
	"net"
	"strings"
	"time"
)

//  sslTries is the maximum number of scan retries
var sslTries = 2

// activeSslAssessments is the number of active assessments according to the manager
var activeSslAssessments = 0

// maxSslAssessments is the maximal number of active assessments
var maxSslAssessments = 10

// NewSslAssessment starts the sslTest for an event
func NewSslAssessment(e Event, eventChannel chan Event, logger *log.Logger) {
	e.senderID = "ssl"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	var dialer = new(net.Dialer)
	dialer.Timeout = 60 * time.Second
	// check if tls connection is possible
	conn, err := tls.DialWithDialer(dialer, "tcp", e.host+":443", nil)
	if err == nil {
		conn.Close()
		if logLevel >= LOG_DEBUG {
			logger.Printf("[DEBUG] SSL available for %v, continuing to API", e.host)
		}
	} else {

		if !strings.Contains(err.Error(), "x509") {
			if logLevel >= LOG_DEBUG {
				logger.Printf("[DEBUG] SSL unavailable for %v: %v", e.host, err.Error())
			}
		} else {
			// if it is an x509 error (mismatch) tls is still possible
			if logLevel >= LOG_DEBUG {
				logger.Printf("[DEBUG] SSL available for %v, with error: %v", e.host, err.Error())

			}
			e.eventType = INTERNAL_ASSESSMENT_COMPLETE
			// Get first IpAddress for DB since we don't have one from the
			// ssllabs-scan
			ip, _ := net.LookupIP(e.host)
			if ip != nil {
				e.report.Endpoints[0].IpAddress = ip[0].String()
			}
			eventChannel <- e
			return
		}
		// test normal connection
		conn, err := net.DialTimeout("tcp", e.host+":http", 60*time.Second)
		if err != nil {
			// no connection possible
			if logLevel >= LOG_INFO {
				logger.Printf("[INFO] HTTP not available for %v, with error: %v", e.host, err.Error())
			}
			e.eventType = INTERNAL_ASSESSMENT_FATAL
			eventChannel <- e
			return
		}
		conn.Close()

		// Get first IpAddress for DB since we don't have one from the
		// ssllabs-scan
		ip, _ := net.LookupIP(e.host)
		if ip != nil {
			e.report.Endpoints[0].IpAddress = ip[0].String()
		}
		e.eventType = INTERNAL_ASSESSMENT_FAILED
		eventChannel <- e
		return

	}

	ip, _ := net.LookupIP(e.host)
	if ip != nil {
		e.report.Endpoints[0].IpAddress = ip[0].String()
	}
	e.eventType = INTERNAL_ASSESSMENT_COMPLETE
	eventChannel <- e
}

// startSslAssessment calls NewSslAssessments as a new goroutine
func (manager *Manager) startSslAssessment(e Event) {
	go NewSslAssessment(e, manager.internalEventChannel, manager.logger)
	activeSslAssessments++
}

// sslRun starts the manager responsible for testing the host connection
func (manager *Manager) sslRun() {
	if logLevel >= LOG_NOTICE {
		manager.logger.Println("[NOTICE] SSLTest-Manager started")
	}
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.internalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {
				activeSslAssessments--
				e.tries++
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] SSLTest for %v failed for the %v. time", e.host, e.tries)
				}
				if e.tries < sslTries {
					manager.startSslAssessment(e)
				} else {
					// http connection is possible
					e.eventType = ERROR
					if logLevel >= LOG_ERROR {
						manager.logger.Printf("[ERROR] SSLTest for %v ultimately failed", e.host)
					}

					e.https = false
					e.report.Reachable = "http"
					e.report.Endpoints[0].Grade = "70"
					manager.ControlEventChannel <- e
				}
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Active assessments: %v", activeSslAssessments)
				}
			}
			if e.eventType == INTERNAL_ASSESSMENT_FATAL {
				activeSslAssessments--
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Active assessments: %v", activeSslAssessments)
				}
				if logLevel >= LOG_ERROR {
					manager.logger.Printf("[ERROR] Connection to %v not possible", e.host)
				}
				// no connection seems to be possible
				e.eventType = FATAL
				e.report.Reachable = "no"
				e.report.Endpoints[0].Grade = "0"
				manager.ControlEventChannel <- e
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] SSL Test starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] SSL Test for %v finished", e.host)
				}

				activeSslAssessments--

				e.eventType = FINISHED
				e.https = true
				e.report.Reachable = "https"
				manager.OutputEventChannel <- e
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Active assessments: %v", activeSslAssessments)
				}

			}
			break
		// if someone asked if there are still active assessments
		case <-manager.CloseChannel:
			manager.CloseChannel <- (activeSslAssessments == 0)
		default:
			<-time.NewTimer(time.Duration(100) * time.Millisecond).C

			if activeSslAssessments < maxSslAssessments {
				select {
				case e := <-manager.InputEventChannel:
					e.tries = 0
					if logLevel >= LOG_DEBUG {
						manager.logger.Println("[DEBUG] New event received")
					}
					manager.startSslAssessment(e)
				case <-time.After(time.Millisecond * 100):
					break
				}
			}

			break
		}
	}
}
