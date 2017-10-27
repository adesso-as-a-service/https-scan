package main

import (
	"crypto/tls"
	"log"
	"net"
	"strings"
	"time"
)

//How often do we try
var sslTries = 2

// How many assessment do we have in progress?
var activeSslAssessments = 0

// The maximum number of assessments we can have in progress at any one time.
var maxSslAssessments = 10

func NewSslAssessment(e Event, eventChannel chan Event, logger *log.Logger) {
	e.senderID = "ssl"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	var dialer = new(net.Dialer)
	dialer.Timeout = 60 * time.Second
	conn, err := tls.DialWithDialer(dialer, "tcp", e.host+":443", nil)
	if err == nil {
		conn.Close()
		if logLevel >= LOG_INFO {
			logger.Printf("[INFO] SSL available for %v, continuing to API", e.host)
		}
	} else {
		if !strings.Contains(err.Error(), "x509") {
			if logLevel >= LOG_DEBUG {
				logger.Printf("[DEBUG] SSL unavailable for %v: %v", e.host, err.Error())
			}
		} else {
			if logLevel >= LOG_INFO {
				logger.Printf("[INFO] SSL available for %v, with error: %v", e.host, err.Error())
			}
		}
		conn, err := net.DialTimeout("tcp", e.host+":http", 60*time.Second)
		if err != nil {
			if logLevel >= LOG_ERROR {
				logger.Printf("[ERROR] HTTP not available for %v, with error: %v", e.host, err.Error())
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

	e.eventType = INTERNAL_ASSESSMENT_COMPLETE
	eventChannel <- e
}

func (manager *Manager) startSslAssessment(e Event) {
	go NewSslAssessment(e, manager.InternalEventChannel, manager.logger)
	activeSslAssessments++
}

func (manager *Manager) sslRun() {
	moreSslAssessments := true
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.InternalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {
				activeSslAssessments--
				manager.logger.Printf("[ERROR] SSL Test for %v failed", e.host)
				if logLevel >= LOG_NOTICE {
					manager.logger.Printf("SSL TEST Active assessments: %v (more: %v)", activeSslAssessments, moreSslAssessments)
				}
				e.tries++
				if e.tries < sslTries {
					manager.startSslAssessment(e)
				} else {
					e.eventType = ERROR
					manager.ControlEventChannel <- e
				}
			}
			if e.eventType == INTERNAL_ASSESSMENT_FATAL {
				activeSslAssessments--
				manager.logger.Printf("[ERROR] SSL Test for %v fateally failed", e.host)
				if logLevel >= LOG_NOTICE {
					manager.logger.Printf("SSL TEST Active assessments: %v (more: %v)", activeSslAssessments, moreSslAssessments)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO]SSL Test starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] SSL Test for %v finished", e.host)
				}

				activeSslAssessments--
				if logLevel >= LOG_NOTICE {
					manager.logger.Printf("SSL TEST Active assessments: %v (more: %v)", activeSslAssessments, moreSslAssessments)
				}
				e.eventType = FINISHED
				e.senderID = "ssl"
				manager.OutputEventChannel <- e

			}

			// Are we done?
			if (activeSslAssessments == 0) && (moreSslAssessments == false) {
				manager.finish("ssl")
				return
			}

			break

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		default:
			<-time.NewTimer(time.Duration(100) * time.Millisecond).C
			if moreSslAssessments {
				if activeSslAssessments < maxSslAssessments {
					e, running := <-manager.InputEventChannel
					if running {
						e.tries = 0
						manager.startSslAssessment(e)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreSslAssessments = false

						if activeSslAssessments == 0 {
							manager.finish("ssl")
							return
						}
					}
				}
			}
			break
		}
	}
}
