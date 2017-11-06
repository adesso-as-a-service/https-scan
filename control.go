// +build go1.3

/*
 * Licensed to Qualys, Inc. (QUALYS) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * QUALYS licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	LOG_NONE     = -1
	LOG_EMERG    = 0
	LOG_ALERT    = 1
	LOG_CRITICAL = 2
	LOG_ERROR    = 3
	LOG_WARNING  = 4
	LOG_NOTICE   = 5
	LOG_INFO     = 6
	LOG_DEBUG    = 7
	LOG_TRACE    = 8
)

var logLevel = LOG_NOTICE

var globalNewAssessmentCoolOff int64 = 1100

var globalIgnoreMismatch = false

var globalStartNew = true

var globalFromCache = false

var globalMaxAge = 0

var globalInsecure = false

var logFile *os.File

//Contains shortNames for all managers, also sets the manager order
var chain = []string{"ssl", "labs", "obs", "secH", "sql"}

type LabsError struct {
	Field   string
	Message string
}

type LabsErrorResponse struct {
	ResponseErrors []LabsError `json:"errors"`
}

func (e LabsErrorResponse) Error() string {
	msg, err := json.Marshal(e)
	if err != nil {
		return err.Error()
	} else {
		return string(msg)
	}
}

type LabsKey struct {
	Size       int
	Strength   int
	Alg        string
	DebianFlaw bool
	Q          int
}

type LabsCert struct {
	Subject              string
	CommonNames          []string
	AltNames             []string
	NotBefore            int64
	NotAfter             int64
	IssuerSubject        string
	SigAlg               string
	IssuerLabel          string
	RevocationInfo       int
	CrlURIs              []string
	OcspURIs             []string
	RevocationStatus     int
	CrlRevocationStatus  int
	OcspRevocationStatus int
	Sgc                  int
	ValidationType       string
	Issues               int
	Sct                  bool
	MustStaple           int
}

type LabsChainCert struct {
	Subject              string
	Label                string
	NotBefore            int64
	NotAfter             int64
	IssuerSubject        string
	IssuerLabel          string
	SigAlg               string
	Issues               int
	KeyAlg               string
	KeySize              int
	KeyStrength          int
	RevocationStatus     int
	CrlRevocationStatus  int
	OcspRevocationStatus int
	Sha1Hash             string
	PinSha256            string
	Raw                  string
}

type LabsChain struct {
	Certs  []LabsChainCert
	Issues int
}

type LabsProtocol struct {
	Id               int
	Name             string
	Version          string
	V2SuitesDisabled bool
	ErrorMessage     bool
	Q                int
}

type LabsSimClient struct {
	Id          int
	Name        string
	Platform    string
	Version     string
	IsReference bool
}

type LabsSimulation struct {
	Client     LabsSimClient
	ErrorCode  int
	Attempts   int
	ProtocolId int
	SuiteId    int
	KxInfo     string
}

type LabsSimDetails struct {
	Results []LabsSimulation
}

type LabsSuite struct {
	Id             int
	Name           string
	CipherStrength int
	DhStrength     int
	DhP            int
	DhG            int
	DhYs           int
	EcdhBits       int
	EcdhStrength   int
	Q              int
}

type LabsSuites struct {
	List       []LabsSuite
	Preference bool
}

type LabsHstsPolicy struct {
	LONG_MAX_AGE      int64
	Header            string
	Status            string
	Error             string
	MaxAge            int64
	IncludeSubDomains bool
	Preload           bool
	Directives        Directives
}

type Directives struct {
	MaxAge            string `json:"max-age"`
	Includesubdomains string
	Preload           string
}

type LabsHstsPreload struct {
	Source     string
	Status     string
	Error      string
	SourceTime int64
}

type LabsHpkpPin struct {
	HashFunction string
	Value        string
}

type LabsHpkpDirective struct {
	Name  string
	Value string
}

type LabsHpkpPolicy struct {
	Header            string
	Status            string
	Error             string
	MaxAge            int64
	IncludeSubDomains bool
	ReportUri         string
	Pins              []LabsHpkpPin
	MatchedPins       []LabsHpkpPin
	Directives        []LabsHpkpDirective
}

type DrownHost struct {
	Ip      string
	Export  bool
	Port    int
	Special bool
	Sslv2   bool
	Status  string
}

type LabsEndpointDetails struct {
	HostStartTime                  int64
	Key                            LabsKey
	Cert                           LabsCert
	Chain                          LabsChain
	Protocols                      []LabsProtocol
	Suites                         LabsSuites
	ServerSignature                string
	PrefixDelegation               bool
	NonPrefixDelegation            bool
	VulnBeast                      bool
	RenegSupport                   int
	SessionResumption              int
	CompressionMethods             int
	SupportsNpn                    bool
	NpnProtocols                   string
	SessionTickets                 int
	OcspStapling                   bool
	StaplingRevocationStatus       int
	StaplingRevocationErrorMessage string
	SniRequired                    bool
	HttpStatusCode                 int
	HttpForwarding                 string
	ForwardSecrecy                 int
	SupportsRc4                    bool
	Rc4WithModern                  bool
	Rc4Only                        bool
	Sims                           LabsSimDetails
	Heartbleed                     bool
	Heartbeat                      bool
	OpenSslCcs                     int
	OpenSSLLuckyMinus20            int
	Poodle                         bool
	PoodleTls                      int
	FallbackScsv                   bool
	Freak                          bool
	HasSct                         int
	DhPrimes                       []string
	DhUsesKnownPrimes              int
	DhYsReuse                      bool
	Logjam                         bool
	ChaCha20Preference             bool
	HstsPolicy                     LabsHstsPolicy
	HstsPreloads                   []LabsHstsPreload
	HpkpPolicy                     LabsHpkpPolicy
	HpkpRoPolicy                   LabsHpkpPolicy
	DrownHosts                     []DrownHost
	DrownErrors                    bool
	DrownVulnerable                bool
}

type LabsEndpoint struct {
	IpAddress            string
	ServerName           string
	StatusMessage        string
	StatusDetailsMessage string
	Grade                string
	GradeTrustIgnored    string
	HasWarnings          bool
	IsExceptional        bool
	Progress             int
	Duration             int
	Eta                  int
	Delegation           int
	Details              LabsEndpointDetails
}

type LabsReport struct {
	Host               string
	Port               int
	Reachable          string
	Protocol           string
	IsPublic           bool
	Status             string
	StatusMessage      string
	StartTime          int64
	TestTime           int64
	EngineVersion      string
	CriteriaVersion    string
	CacheExpiryTime    int64
	Endpoints          []LabsEndpoint
	CertHostnames      []string
	rawJSON            string
	HeaderScore        Securityheaders
	ObservatoryScan    ObservatoryAnalyzeResult
	ObservatoryResults ObservatoryScanResults
}

type LabsResults struct {
	reports   []LabsReport
	responses []string
}

type LabsInfo struct {
	EngineVersion        string
	CriteriaVersion      string
	MaxAssessments       int
	CurrentAssessments   int
	NewAssessmentCoolOff int64
	Messages             []string
}

type Event struct {
	host      string
	senderID  string
	eventType int
	report    *LabsReport
	tries     int
	https     bool
}

const (
	FATAL    = -3 // direct to sql, if used
	REERROR  = -2 // Retrying Error
	ERROR    = -1 // Try Next Manager Error
	FINISHED = 0
)

type HostProvider struct {
	hostnames   []string
	StartingLen int
}

func NewHostProvider(hs []string) *HostProvider {
	hostnames := make([]string, len(hs))
	copy(hostnames, hs)
	hostProvider := HostProvider{hostnames, len(hs)}
	return &hostProvider
}

func (hp *HostProvider) next() (string, bool) {
	if len(hp.hostnames) == 0 {
		return "", false
	}

	var e string
	e, hp.hostnames = hp.hostnames[0], hp.hostnames[1:]

	return e, true
}

type Manager struct {
	InputEventChannel    chan Event
	OutputEventChannel   chan Event
	InternalEventChannel chan Event
	ControlEventChannel  chan Event
	CloseChannel         chan bool
	logger               *log.Logger
}

func NewManager(InputEventChannel chan Event, ControlEventChannel chan Event, id string) *Manager {
	manager := Manager{
		InputEventChannel:    InputEventChannel,
		OutputEventChannel:   make(chan Event),
		InternalEventChannel: make(chan Event),
		ControlEventChannel:  ControlEventChannel,
		CloseChannel:         make(chan bool),
	}

	go manager.run(id)

	return &manager
}

func (manager *Manager) run(id string) error {
	switch {
	case id == "ssl":
		manager.logger = log.New(io.MultiWriter(os.Stdout, logFile), "SSLTest: ", log.Ldate|log.Ltime)
		manager.sslRun()
		break
	case id == "labs":
		manager.logger = log.New(io.MultiWriter(os.Stdout, logFile), "SSLLabs: ", log.Ldate|log.Ltime)
		manager.labsRun()
		break
	case id == "obs":
		manager.logger = log.New(io.MultiWriter(os.Stdout, logFile), "Obs.:    ", log.Ldate|log.Ltime)
		manager.obsRun()
		break
	case id == "secH":
		manager.logger = log.New(io.MultiWriter(os.Stdout, logFile), "SecH:    ", log.Ldate|log.Ltime)
		manager.secHRun()
		break
	case id == "sql":
		manager.logger = log.New(io.MultiWriter(os.Stdout, logFile), "SQLwrt:  ", log.Ldate|log.Ltime)
		manager.sqlRun()
		break
	default:
		return fmt.Errorf("undefined manager.run() for id: %v", id)
	}
	return nil
}

type ErrorHandler struct {
	errorList         []Event
	InputEventChannel chan Event
	QuestionChannel   chan bool
	channelMap        map[string][2]chan Event
	useing            map[string]bool
}

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

func (errorHandler *ErrorHandler) run() {
	logger := log.New(io.MultiWriter(os.Stdout, logFile), "ErrHand: ", log.Ltime|log.Ldate)
	if logLevel >= LOG_NOTICE {
		logger.Println("[NOTICE] ErrorHandler started")
	}
	for {
		select {
		//Receive Error from Control
		case e := <-errorHandler.InputEventChannel:
			if logLevel >= LOG_INFO {
				logger.Printf("[INFO] Received Error for %v from %v", e.host, e.senderID)
			}
			e.tries = 0
			//add Error to the ErrorQueue
			errorHandler.errorList = append(errorHandler.errorList, e)
			break
		//Receive Error Check from Control
		case <-errorHandler.QuestionChannel:
			if logLevel >= LOG_DEBUG {
				logger.Println("[DEBUG] Error Check from Control received")
			}
			if len(errorHandler.errorList) == 0 {
				//No more Errors
				errorHandler.QuestionChannel <- true
			} else {
				//Still errors
				errorHandler.QuestionChannel <- false
			}
			break
		default:
			//Select an Error and try to send it to the next manager
			if len(errorHandler.errorList) != 0 {
				var tryEvent Event
				tryEvent, errorHandler.errorList = errorHandler.errorList[0], errorHandler.errorList[1:]
				var channel chan Event
				if tryEvent.eventType == FINISHED {

					//Select target channel for error
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
				}

				//Try sending error
				select {
				case channel <- tryEvent:
					if logLevel >= LOG_INFO {
						logger.Printf("[INFO] 1 Error cleared! %v remaining. Send %v from %v", len(errorHandler.errorList), tryEvent.host, tryEvent.senderID)
					}
					break
				case <-time.After(time.Millisecond * 100):
					//Timeout try next error in ErrorQueue
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

type MasterManager struct {
	hostProvider        *HostProvider
	InputEventChannel   chan Event
	OutputEventChannel  chan Event
	ControlEventChannel chan Event
	MainChannel         chan bool
	useing              map[string]bool
	results             *LabsResults
	managerList         []Manager
	logger              *log.Logger
}

func NewMasterManager(hostProvider *HostProvider, useing map[string]bool) *MasterManager {
	manager := MasterManager{
		hostProvider:        hostProvider,
		ControlEventChannel: make(chan Event),
		InputEventChannel:   nil,
		OutputEventChannel:  make(chan Event),
		MainChannel:         make(chan bool),
		useing:              useing,
		results:             &LabsResults{reports: make([]LabsReport, 0)},
		managerList:         make([]Manager, len(chain)),
		logger:              log.New(io.MultiWriter(os.Stdout, logFile), "Control: ", log.Ldate|log.Ltime),
	}

	go manager.run()

	return &manager
}

func (manager *MasterManager) buildChain() {
	num := 0
	for _, id := range chain {
		if manager.useing[id] {
			if num == 0 {
				manager.managerList[num] = *NewManager(manager.OutputEventChannel, manager.ControlEventChannel, id)
			} else {
				manager.managerList[num] = *NewManager(manager.managerList[num-1].OutputEventChannel, manager.ControlEventChannel, id)
			}
			num = num + 1
		}

	}
}

func (manager *MasterManager) handleResult(e Event) {
	manager.results.reports = append(manager.results.reports, *e.report)
	manager.results.responses = append(manager.results.responses, e.report.rawJSON)
}

func checkCloseManager(manager Manager) bool {
	select {
	case manager.CloseChannel <- true:
		select {
		case b := <-manager.CloseChannel:
			if !b {
				return false
			}
		case <-time.After(time.Millisecond * 500):
			return false
		}
	case <-time.After(time.Millisecond * 500):
		return false
	}
	//No more active assesments for manager
	return true
}

func checkCloseErr(errH *ErrorHandler) bool {
	select {
	case errH.QuestionChannel <- true:
		select {
		case b := <-errH.QuestionChannel:
			if !b {
				return false
			}
		case <-time.After(time.Millisecond * 500):
			return false
		}
	case <-time.After(time.Millisecond * 500):
		return false
	}
	//No more active assesments for errH
	return true
}

func (manager *MasterManager) checkClose(errH *ErrorHandler) bool {
	for _, id := range manager.managerList {
		if !checkCloseManager(id) {
			return false
		}
		if !checkCloseErr(errH) {
			return false
		}
	}
	return true
}

func (manager *MasterManager) run() {
	if logLevel >= LOG_NOTICE {
		manager.logger.Println("[NOTICE] Control-Manager started")
	}
	//starting needed managers and assign their channels
	manager.buildChain()
	if logLevel >= LOG_DEBUG {
		manager.logger.Println("[DEBUG] Manager-chain build successful")
	}

	var channelMap = make(map[string][2]chan Event, len(chain))
	num := 0
	for _, id := range chain {
		if manager.useing[id] {
			channelMap[id] = [2]chan Event{manager.managerList[num].InputEventChannel,
				manager.managerList[num].OutputEventChannel}
			num = num + 1
		}
	}
	var errorChan = make(chan Event)
	var errorQuestionChan = make(chan bool)
	//Starting ErrorHandler for failed entries
	errH := NewErrorHandler(errorChan, errorQuestionChan, channelMap, manager.useing)

	if logLevel >= LOG_DEBUG {
		manager.logger.Println("[DEBUG] ErrorHandler started successful")
	}

	//Input-Channel for Control is the last output channel
	manager.InputEventChannel = manager.managerList[num-1].OutputEventChannel

	//Get first host-enty for testing
	host, hasNext := manager.hostProvider.next()

	var e Event
	//create empty Event for host if there is one
	if hasNext {
		e = Event{host, "master", 0, nil, 0, false}
		report := LabsReport{
			Host:      e.host,
			Reachable: "unknown",
			Endpoints: []LabsEndpoint{
				LabsEndpoint{
					Grade: "",
				},
			},
			Port: 0,
		}
		e.report = &report
	} else {
		//Stop if there is no host in the list
		if logLevel >= LOG_ERROR {
			manager.logger.Println("[ERROR] The given HostList is empty. Stopping execution")
		}
		close(manager.MainChannel)
		return
	}

	hasElements := true

	//Starting Control-Loop
	if logLevel >= LOG_NOTICE {
		manager.logger.Println("[NOTICE] Starting Control-Loop")
	}
	for {
		//If there are still unsent entries
		if hasElements {
			select {
			case manager.OutputEventChannel <- e:
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] %v is next in line for assessment", e.host)
				}
				//Get next host-entry
				host, hasNext := manager.hostProvider.next()
				if hasNext {
					e = Event{host, "master", 0, nil, 0, false}
					report := LabsReport{
						Host:      e.host,
						Reachable: "unknown",
						Endpoints: []LabsEndpoint{
							LabsEndpoint{
								Grade: "",
							},
						},
						Port: 0,
					}
					e.report = &report
				} else {
					//No more hosts in the list
					if logLevel >= LOG_NOTICE {
						manager.logger.Println("[NOTICE] Assessment for all hosts has started")
					}
					hasElements = false
				}
				break
			case cE := <-manager.ControlEventChannel:
				//Handle Messages on the Control-Channel
				switch cE.eventType {
				case ERROR:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO] Assessment failed for %v, for the %v. time in %v", e.host, e.tries, e.senderID)
					}
					switch cE.senderID {
					case "ssl":
						cE.eventType = FINISHED
						errorChan <- cE
						break
					case "labs":
						cE.eventType = FINISHED
						errorChan <- cE
						break
					case "obs":
						cE.eventType = FINISHED
						errorChan <- cE
					case "secH":
						cE.eventType = FINISHED
						errorChan <- cE
						break
					default:
						if logLevel >= LOG_WARNING {
							manager.logger.Printf("[WARNING] Assessment of %v has ultimately failed in %v", e.host, e.senderID)
						}
						break
					}
				case REERROR:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO]  %v will be retried in %v", e.host, e.senderID)
					}
					errorChan <- cE
				}
				break
			case iE := <-manager.InputEventChannel:
				//Handle incomming results
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Results for %v received", e.host)
				}
				manager.handleResult(iE)
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] Results for %v have been handled", e.host)
				}
				break
			}
		} else {
			select {
			case cE := <-manager.ControlEventChannel:
				//Handle Messages on the Control-Channel
				switch cE.eventType {
				case ERROR:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO] Assessment failed for %v, for the %v. time in %v", e.host, e.tries, e.senderID)
					}
					switch cE.senderID {
					case "ssl":
						cE.eventType = FINISHED
						errorChan <- cE
						break
					case "labs":
						cE.eventType = FINISHED
						errorChan <- cE
						break
					case "obs":
						cE.eventType = FINISHED
						errorChan <- cE
					case "secH":
						cE.eventType = FINISHED
						errorChan <- cE
						break
					default:
						if logLevel >= LOG_WARNING {
							manager.logger.Printf("[WARNING] Assessment of %v has ultimately failed in %v", e.host, e.senderID)
						}
						break
					}

				}
				break
			case iE := <-manager.InputEventChannel:
				//Handle incomming results
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Results for %v received", e.host)
				}
				manager.handleResult(iE)
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] Results for %v have been handled", e.host)
				}
				break
			case <-time.After(time.Millisecond * 2000):
				//Check if there is a channel ready for closing
				if logLevel >= LOG_DEBUG {
					manager.logger.Println("[DEBUG] Checking if scan is finished!")
				}
				if manager.checkClose(errH) {
					if logLevel >= LOG_NOTICE {
						manager.logger.Println("[NOTICE] Scan complete")
					}
					//Are there still Errors to handle
					close(manager.MainChannel)
				}
				if logLevel >= LOG_DEBUG {
					manager.logger.Println("[DEBUG] Scan not finished!")
				}
				break
			}
		}
	}
}

func parseLogLevel(level string) int {
	switch {
	case level == "error":
		return LOG_ERROR
	case level == "notice":
		return LOG_NOTICE
	case level == "info":
		return LOG_INFO
	case level == "debug":
		return LOG_DEBUG
	case level == "trace":
		return LOG_TRACE
	}

	log.Fatalf("[ERROR] Unrecognized log level: %v", level)
	return -1
}

func flattenJSON(inputJSON map[string]interface{}, rootKey string, flattened *map[string]interface{}) {
	var keysep = "." // Char to separate keys
	var Q = "\""     // Char to envelope strings

	for rkey, value := range inputJSON {
		key := rootKey + rkey
		if _, ok := value.(string); ok {
			(*flattened)[key] = Q + value.(string) + Q
		} else if _, ok := value.(float64); ok {
			(*flattened)[key] = fmt.Sprintf("%.f", value)
		} else if _, ok := value.(bool); ok {
			(*flattened)[key] = value.(bool)
		} else if _, ok := value.([]interface{}); ok {
			for i := 0; i < len(value.([]interface{})); i++ {
				aKey := key + keysep + strconv.Itoa(i)
				if _, ok := value.([]interface{})[i].(string); ok {
					(*flattened)[aKey] = Q + value.([]interface{})[i].(string) + Q
				} else if _, ok := value.([]interface{})[i].(float64); ok {
					(*flattened)[aKey] = value.([]interface{})[i].(float64)
				} else if _, ok := value.([]interface{})[i].(bool); ok {
					(*flattened)[aKey] = value.([]interface{})[i].(bool)
				} else {
					flattenJSON(value.([]interface{})[i].(map[string]interface{}), key+keysep+strconv.Itoa(i)+keysep, flattened)
				}
			}
		} else if value == nil {
			(*flattened)[key] = nil
		} else {
			flattenJSON(value.(map[string]interface{}), key+keysep, flattened)
		}
	}
}

func flattenAndFormatJSON(inputJSON []byte) *[]string {
	var flattened = make(map[string]interface{})

	mappedJSON := map[string]interface{}{}
	err := json.Unmarshal(inputJSON, &mappedJSON)
	if err != nil {
		log.Fatalf("[ERROR] Reconsitution of JSON failed: %v", err)
	}

	// Flatten the JSON structure, recursively
	flattenJSON(mappedJSON, "", &flattened)

	// Make a sorted index, so we can print keys in order
	kIndex := make([]string, len(flattened))
	ki := 0
	for key, _ := range flattened {
		kIndex[ki] = key
		ki++
	}
	sort.Strings(kIndex)

	// Ordered flattened data
	var flatStrings []string
	for _, value := range kIndex {
		flatStrings = append(flatStrings, fmt.Sprintf("\"%v\": %v\n", value, flattened[value]))
	}
	return &flatStrings
}

func readLines(path *string) ([]string, error) {
	file, err := os.Open(*path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	br := bufio.NewReader(file)
	r, _, err := br.ReadRune()
	if err != nil {
		log.Fatalf("[ERROR] Failed reading Byte Order Marking: %v", err.Error())
	}
	if r != '\uFEFF' {
		br.UnreadRune()
	}
	scanner := bufio.NewScanner(br)
	for scanner.Scan() {
		var line = strings.TrimSpace(scanner.Text())
		if (!strings.HasPrefix(line, "#")) && (line != "") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func validateURL(URL string) bool {
	_, err := url.Parse(URL)
	if err != nil {
		return false
	} else {
		return true
	}
}

func validateHostname(hostname string) bool {
	addrs, err := net.LookupHost(hostname)

	// In some cases there is no error
	// but there are also no addresses
	if err != nil || len(addrs) < 1 {
		return false
	} else {
		return true
	}
}

func main() {
	startTime := time.Now()
	var conf_api = flag.String("api", "BUILTIN", "API entry point, for example https://www.example.com/api/")
	var conf_grade = flag.Bool("grade", false, "Output only the hostname: grade")
	var conf_hostcheck = flag.Bool("hostcheck", false, "If true, host resolution failure will result in a fatal error.")
	var conf_hostfile = flag.String("hostfile", "", "File containing hosts to scan (one per line)")
	var conf_ignore_mismatch = flag.Bool("ignore-mismatch", false, "If true, certificate hostname mismatch does not stop assessment.")
	var conf_insecure = flag.Bool("insecure", false, "Skip certificate validation. For use in development only. Do not use.")
	var conf_json_flat = flag.Bool("json-flat", false, "Output results in flattened JSON format")
	var conf_quiet = flag.Bool("quiet", false, "Disable status messages (logging)")
	var conf_usecache = flag.Bool("usecache", false, "If true, accept cached results (if available), else force live scan.")
	var conf_maxage = flag.Int("maxage", 0, "Maximum acceptable age of cached results, in hours. A zero value is ignored.")
	var conf_verbosity = flag.String("verbosity", "notice", "Configure log verbosity: error, notice, info, debug, or trace.")
	var conf_version = flag.Bool("version", false, "Print version and API location information and exit")

	//Added Flags
	var conf_securityheaders = flag.Bool("no-securityheaders", false, "Don't include a scan for security headers")
	var conf_sql_retries = flag.Int("sql-retries", 3, "Number of retries if the SQL-connection fails")
	var conf_observatory = flag.Bool("no-observatory", false, "Don't include a scan using the mozilla observatory API")
	var conf_ssllabs = flag.Bool("no-ssllabs", false, "Don't use SSLlabs-Scan")
	var conf_ssltest = flag.Bool("no-ssltest", false, "Don't test hosts before starting Scan")
	var conf_sql = flag.Bool("no-sql", false, "Don't write results into the database")

	var conf_sslTries = flag.Int("sslTest-tries", 2, "Number of tries if the sslTest fails")
	var conf_labsTries = flag.Int("labs-tries", 1, "Number of tries if the sslLabs-Scan fails")
	var conf_obsTries = flag.Int("obs-tries", 2, "Number of tries if the Observatory-Scan fails")
	var conf_secHTries = flag.Int("secH-tries", 3, "Number of tries if the Securityheader-Scan fails")

	flag.Parse()

	sslTries = *conf_sslTries
	obsTries = *conf_obsTries
	labsTries = *conf_labsTries
	secHTries = *conf_secHTries

	if sslTries < 1 {
		sslTries = 1
	}

	if labsTries < 1 {
		labsTries = 1
	}
	if obsTries < 1 {
		obsTries = 1
	}

	if secHTries < 1 {
		secHTries = 1
	}

	globalSQLRetries = *conf_sql_retries

	if !*conf_observatory {
		globalObservatory = true
	}

	if !*conf_securityheaders {
		globalSecurityheaders = true
	}

	if *conf_version {
		fmt.Println(USER_AGENT)
		fmt.Println("API location: " + apiLocation)
		return
	}

	logLevel = parseLogLevel(strings.ToLower(*conf_verbosity))

	globalIgnoreMismatch = *conf_ignore_mismatch

	if *conf_quiet {
		logLevel = LOG_NONE
	}

	// We prefer cached results
	if *conf_usecache {
		globalFromCache = true
		globalStartNew = false
	}

	if *conf_maxage != 0 {
		globalMaxAge = *conf_maxage
	}

	// Verify that the API entry point is a URL.
	if *conf_api != "BUILTIN" {
		apiLocation = *conf_api
	}

	if validateURL(apiLocation) == false {
		log.Fatalf("[ERROR] Invalid API URL: %v", apiLocation)
	}

	var hostnames []string

	if *conf_hostfile != "" {
		// Open file, and read it
		var err error
		hostnames, err = readLines(conf_hostfile)
		if err != nil {
			log.Fatalf("[ERROR] Reading from specified hostfile failed: %v", err)
		}

	} else {
		// Read hostnames from the rest of the args
		hostnames = flag.Args()
	}

	if *conf_hostcheck {
		// Validate all hostnames before we attempt to test them. At least
		// one hostname is required.
		for _, host := range hostnames {
			if validateHostname(host) == false {
				log.Fatalf("[ERROR] Invalid hostname: %v", host)
			}
		}
	}

	if *conf_insecure {
		globalInsecure = *conf_insecure
	}

	if *conf_ssllabs && *conf_ssltest && *conf_observatory && *conf_securityheaders {
		log.Fatal("[ERROR] At least one can has to be run!")
	}
	var useing = map[string]bool{"labs": !*conf_ssllabs, "obs": !*conf_observatory, "secH": !*conf_securityheaders, "sql": !*conf_sql, "ssl": !*conf_ssltest}

	err := os.Mkdir("log", 0700)
	if err != nil && os.IsNotExist(err) {
		log.Fatalf("[FATAL] Could not create loggingFolder log: %v", err.Error())
	}

	err = os.Mkdir("results", 0700)
	if err != nil && os.IsNotExist(err) {
		log.Fatalf("[FATAL] Could not create resultFolder res: %v", err.Error())
	}

	FileName := time.Now().Format("2006_01_02_150405")
	logFile, err = os.Create("log/" + FileName + ".log")

	if err != nil {
		log.Fatalf("[FATAL] Could not create logging File %v: %v", "log/"+FileName+".log", err.Error())
	}
	defer logFile.Close()

	resFile, err := os.Create("results/" + FileName + ".result")

	if err != nil {
		log.Fatalf("[FATAL] Could not create resultFile %v: %v", "results/"+FileName+".result", err.Error())
	}
	defer resFile.Close()

	hp := NewHostProvider(hostnames)
	manager := NewMasterManager(hp, useing)

	// Respond to events until all the work is done.
	for {
		_, running := <-manager.MainChannel
		if running == false {
			var results []byte
			var err error

			if hp.StartingLen == 0 {
				return
			}

			if *conf_grade {
				// Just the grade(s). We use flatten and RAW
				/*
					"endpoints.0.grade": "A"
					"host": "testing.spatialkey.com"
				*/
				for i := range manager.results.responses {
					results := []byte(manager.results.responses[i])

					name := ""
					grade := ""

					flattened := flattenAndFormatJSON(results)

					for _, fval := range *flattened {
						if strings.HasPrefix(fval, "\"host\"") {
							// hostname
							parts := strings.Split(fval, ": ")
							name = strings.TrimSuffix(parts[1], "\n")
							if grade != "" {
								break
							}
						} else if strings.HasPrefix(fval, "\"endpoints.0.grade\"") {
							// grade
							parts := strings.Split(fval, ": ")
							grade = strings.TrimSuffix(parts[1], "\n")
							if name != "" {
								break
							}
						}
					}
					if grade != "" && name != "" {
						fmt.Fprintln(resFile, name+": "+grade)
					}
				}
			} else if *conf_json_flat {
				// Flat JSON and RAW

				for i := range manager.results.responses {
					results := []byte(manager.results.responses[i])

					flattened := flattenAndFormatJSON(results)

					// Print the flattened data
					fmt.Fprintln(resFile, *flattened)
				}
			} else {
				// Raw (non-Go-mangled) JSON output

				fmt.Fprintln(resFile, "[")
				for i := range manager.results.responses {
					results := manager.results.responses[i]

					if i > 0 {
						fmt.Fprintln(resFile, ",")
					}
					fmt.Fprintln(resFile, results)
				}
				fmt.Fprintln(resFile, "]")
			}

			if err != nil {
				log.Fatalf("[ERROR] Result-Output to JSON failed: %v", err)
			}

			fmt.Fprintln(resFile, string(results))

			if logLevel >= LOG_INFO {
				log.Println("[INFO] All assessments complete; shutting down")
			}
			elapsed := time.Since(startTime)
			log.Printf("It took %s", elapsed)
			return
		}
	}
}
