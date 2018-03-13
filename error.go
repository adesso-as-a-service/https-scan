package main

import (
	"io"
	"log"
	"os"
	"time"
)

// ErrorHandler defines a unit that is responsible for handling the diffrent event
// errors that can occur
type ErrorHandler struct {
	// errorList is queue with all the errors that need to be handled
	errorList []Event
	// InputEventChannel is a channel for incoming events that
	// experienced an error during analysis
	InputEventChannel chan Event
	// QuestionChannel  is a channel which allows one to ask the ErrorHandler,
	// if there are still errors in his queue
	QuestionChannel chan bool
	// channelMap maps the senderID to the corresponding Input- and OutputEventChannel
	channelMap map[string][2]chan Event
	// useing maps the senderID to a bool, which is true if the specified step is used
	useing map[string]bool
}

// NewErrorHandler creates and starts an errorHandler with the specified parameters.
func NewErrorHandler(InputEventChannel chan Event, QuestionChannel chan bool, channelMap map[string][2]chan Event, useing map[string]bool) *ErrorHandler {
	errorHandler := ErrorHandler{
		InputEventChannel: InputEventChannel,
		QuestionChannel:   QuestionChannel,
		channelMap:        channelMap,
		useing:            useing,
	}
	go errorHandler.run()
	return &errorHandler
}

// run starts the ErrorHandler
func (errorHandler *ErrorHandler) run() {
	// setting logger for ErrorHandler
	logger := log.New(io.MultiWriter(os.Stdout, logFile), "ErrHand: ", log.Ltime|log.Ldate)
	if logLevel >= LOG_NOTICE {
		logger.Println("[NOTICE] ErrorHandler started")
	}

	for {
		select {
		// Receive Error from Control
		case e := <-errorHandler.InputEventChannel:
			if logLevel >= LOG_INFO {
				logger.Printf("[INFO] Received Error for %v from %v", e.host, e.senderID)
			}
			e.tries = 0
			// add Error to the ErrorQueue
			errorHandler.errorList = append(errorHandler.errorList, e)
			break
		// Receive Error Check from Control
		case <-errorHandler.QuestionChannel:
			if logLevel >= LOG_DEBUG {
				logger.Println("[DEBUG] Error Check from Control received")
			}
			if len(errorHandler.errorList) == 0 || errorHandler.errorList == nil {
				// No more Errors
				errorHandler.QuestionChannel <- true
			} else {
				// Still errors
				errorHandler.QuestionChannel <- false
			}
			break
		default:
			// Select an Error and try to send it to the next manager
			if len(errorHandler.errorList) != 0 {
				// get next error in queue
				var tryEvent Event
				tryEvent, errorHandler.errorList = errorHandler.errorList[0], errorHandler.errorList[1:]
				var channel chan Event
				// select channel to send this error to according to sender
				// and errorType
				if tryEvent.eventType == FINISHED {
					switch tryEvent.senderID {
					case "labs":
						channel = errorHandler.channelMap["labs"][1]
						break
					case "ssl":
						if errorHandler.useing["labs"] {
							channel = errorHandler.channelMap["labs"][1]
						} else {
							channel = errorHandler.channelMap["ssl"][1]
						}
						break
					case "obs":
						channel = errorHandler.channelMap["obs"][1]
						break
					case "secH":
						channel = errorHandler.channelMap["secH"][1]
						break
					}
				} else if tryEvent.eventType == REERROR {
					channel = errorHandler.channelMap[tryEvent.senderID][0]
				} else if tryEvent.eventType == FATAL {
					channel = errorHandler.channelMap["sql"][0]
				}

				// Try sending error
				select {
				case channel <- tryEvent:
					if logLevel >= LOG_INFO {
						logger.Printf("[INFO] 1 Error cleared! %v remaining. Send %v from %v", len(errorHandler.errorList), tryEvent.host, tryEvent.senderID)
					}
					break
				case <-time.After(time.Millisecond * 100):
					// Timeout: put error at the back of the queue
					errorHandler.errorList = append(errorHandler.errorList, tryEvent)
					break
				}
				if logLevel >= LOG_DEBUG {
					logger.Printf("[DEBUG] %v Errors remaining in ErrorQueue", len(errorHandler.errorList))
				}
			}
		}
	}

}

// checkClose tests if there are errors in errHs error queue at the moment. If so it
// returns true
func checkCloseErr(errH *ErrorHandler) bool {
	select {
	// ask error handler
	case errH.QuestionChannel <- true:
		select {
		// receive answer
		case b := <-errH.QuestionChannel:
			if !b {
				// error handler still working: false
				log.Println("[DEBUG] Error Handler still has errors!")
				return false
			}
		// no answer: false
		case <-time.After(time.Millisecond * 500):
			log.Println("[DEBUG] Error Handler wont answer 'Closed Question'!")
			return false
		}
	// not reached: false
	case <-time.After(time.Millisecond * 500):
		log.Println("[DEBUG] Error Handler wont receive 'Closed Question'!")
		return false
	}
	// No more active assessments for errH
	return true
}
