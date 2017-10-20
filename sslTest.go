package main

import (
	"crypto/tls"
	"log"
	"net"
	"strings"
	"time"
)

// How many assessment do we have in progress?
var activeSslAssessments = 0

// The maximum number of assessments we can have in progress at any one time.
var maxSslAssessments = 10

func NewSslAssessment(e Event, eventChannel chan Event) {
	e.senderID = "ssl"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	conn, err := tls.Dial("tcp", e.host+":443", nil)
	if err == nil {
		conn.Close()
		if logLevel >= LOG_INFO {
			log.Printf("[INFO] SSL available for %v, continuing to API", e.host)
		}
	} else {
		if !strings.Contains(err.Error(), "x509") {
			if logLevel >= LOG_DEBUG {
				log.Printf("[DEBUG] SSL unavailable for %v: %v", e.host, err.Error())
			}
		} else {
			if logLevel >= LOG_INFO {
				log.Printf("[INFO] SSL available for %v, with error: %v", e.host, err.Error())
			}
		}
		conn, err := net.Dial("tcp", e.host+":http")
		if err != nil {
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] HTTP not available for %v, with error: %v", e.host, err.Error())
			}
			return
		}
		conn.Close()
		report := LabsReport{
			Host: e.host,
			Endpoints: []LabsEndpoint{
				LabsEndpoint{
					Grade: "70",
				},
			},
			Port: 0,
		}

		e.report = report

		// Get first IpAddress for DB since we don't have one from the
		// ssllabs-scan
		ip, _ := net.LookupIP(e.host)
		if ip != nil {
			e.report.Endpoints[0].IpAddress = ip[0].String()
		}

	}

	e.eventType = INTERNAL_ASSESSMENT_COMPLETE
	eventChannel <- e
}

func (manager *Manager) startSslAssessment(e Event) {
	go NewSslAssessment(e, manager.InternalEventChannel)
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
				log.Printf("[ERROR] SSL Test for %v failed", e.host)
				//TODO ERROR handeling
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_INFO {
					log.Printf("[INFO]SSL Test starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_INFO {
					log.Printf("[INFO] SSL Test for %v finished", e.host)
				}

				activeSslAssessments--

				e.eventType = FINISHED
				e.senderID = "ssl"
				manager.OutputEventChannel <- e

				if logLevel >= LOG_DEBUG {
					log.Printf("[DEBUG] Active assessments: %v (more: %v)", activeSslAssessments, moreSslAssessments)
				}
			}

			// Are we done?
			if (activeSslAssessments == 0) && (moreSslAssessments == false) {
				manager.finish("obs")
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
						manager.startObsAssessment(e)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreSslAssessments = false

						if activeObsAssessments == 0 {
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
