// +build go1.3

/*
 * Includes modified parts from Qualys, Inc. (QUALYS)s ssllabs-scan.
 * ssllabs-scan is released under the the Apache License, Version 2.0
 * (sourcecode @ https://github.com/ssllabs/ssllabs-scan)
 * In accordance with this license, a copy of the license is included
 * in the package.
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

// Diffrent Log-Levels
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

// logLevel sets the global verbosity of thr Logging
var logLevel int

// globalIgnoreMismatch, when true hostname mismatches are ignored
var globalIgnoreMismatch = false

// globalStartNew, when true no cached results are used
var globalStartNew = true

// globalFromCache, is equal to !globalStartNew
var globalFromCache = false

// globalMaxAge sets the highest accepted age in hours for cached results
var globalMaxAge = 0

// globalInsecure, when true certificates aren't validated (DON'T USE)
var globalInsecure = false

// logFile references the log-File, which is used to store the log of the current run
var logFile *os.File

// chain contains all ids of the implemented managers. The order in this string is the order
// in which the hosts pass the managers
var chain = []string{"ssl", "labs", "obs", "secH", "sql"}

// The following structs are modified structs from ssllabs-scan and
// hold  information and results for the scan

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

type LabsCaaRecord struct {
	Tag   string
	Value string
	Flags int
}

type LabsCaaPolicy struct {
	PolicyHostname string
	CaaRecords     []LabsCaaRecord
}

type LabsCert struct {
	Id                     string
	Subject                string
	CommonNames            []string
	AltNames               []string
	NotBefore              int64
	NotAfter               int64
	IssuerSubject          string
	SigAlg                 string
	RevocationInfo         int
	CrlURIs                []string
	OcspURIs               []string
	RevocationStatus       int
	CrlRevocationStatus    int
	OcspRevocationStatus   int
	DnsCaa                 bool
	Caapolicy              LabsCaaPolicy
	MustStaple             bool
	Sgc                    int
	ValidationType         string
	Issues                 int
	Sct                    bool
	Sha1Hash               string
	PinSha256              string
	KeyAlg                 string
	KeySize                int
	KeyStrength            int
	KeyKnownDebianInsecure bool
	Raw                    string
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
	Client         LabsSimClient
	ErrorCode      int
	ErrorMessage   string
	Attempts       int
	CertChainId    string
	ProtocolId     int
	SuiteId        int
	SuiteName      string
	KxType         string
	KxStrength     int
	DhBits         int
	DhP            int
	DhG            int
	DhYs           int
	NamedGroupBits int
	NamedGroupId   int
	NamedGroupName string
	AlertType      int
	AlertCode      int
	KeyAlg         string
	KeySize        int
	SigAlg         string
}

type LabsSimDetails struct {
	Results []LabsSimulation
}

type LabsSuite struct {
	Id             int
	Name           string
	CipherStrength int
	KxType         string
	KxStrength     int
	DhBits         int
	DhP            int
	DhG            int
	DhYs           int
	NamedGroupBits int
	NamedGroupId   int
	NamedGroudName string
	Q              int
}

type LabsSuites struct {
	Protocol   int
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
	Directives        map[string]string
}

type LabsHstsPreload struct {
	Source     string
	HostName   string
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

type LabsDrownHost struct {
	Ip      string
	Export  bool
	Port    int
	Special bool
	Sslv2   bool
	Status  string
}

type LabsCertChain struct {
	Id        string
	CertIds   []string
	Trustpath []LabsTrustPath
	Issues    int
	NoSni     bool
}

type LabsTrustPath struct {
	CertIds       []string
	Trust         []LabsTrust
	IsPinned      bool
	MatchedPins   int
	UnMatchedPins int
}

type LabsTrust struct {
	RootStore         string
	IsTrusted         bool
	TrustErrorMessage string
}

type LabsNamedGroups struct {
	List       []LabsNamedGroup
	Preference bool
}

type LabsNamedGroup struct {
	Id   int
	Name string
	Bits int
}

type LabsHttpTransaction struct {
	RequestUrl        string
	StatusCode        int
	RequestLine       string
	RequestHeaders    []string
	ResponseLine      string
	ResponseRawHeader []string
	ResponseHeader    []LabsHttpHeader
	FragileServer     bool
}

type LabsHttpHeader struct {
	Name  string
	Value string
}

type LabsEndpointDetails struct {
	HostStartTime                  int64
	CertChains                     []LabsCertChain
	Protocols                      []LabsProtocol
	Suites                         []LabsSuites
	NoSniSuites                    LabsSuites
	NamedGroups                    LabsNamedGroups
	ServerSignature                string
	PrefixDelegation               bool
	NonPrefixDelegation            bool
	VulnBeast                      bool
	RenegSupport                   int
	SessionResumption              int
	CompressionMethods             int
	SupportsNpn                    bool
	NpnProtocols                   string
	SupportsAlpn                   bool
	AlpnProtocols                  string
	SessionTickets                 int
	OcspStapling                   bool
	StaplingRevocationStatus       int
	StaplingRevocationErrorMessage string
	SniRequired                    bool
	HttpStatusCode                 int
	HttpForwarding                 string
	SupportsRc4                    bool
	Rc4WithModern                  bool
	Rc4Only                        bool
	ForwardSecrecy                 int
	ProtocolIntolerance            int
	MiscIntolerance                int
	Sims                           LabsSimDetails
	Heartbleed                     bool
	Heartbeat                      bool
	OpenSslCcs                     int
	OpenSSLLuckyMinus20            int
	Ticketbleed                    int
	Bleichenbacher                 int
	Poodle                         bool
	PoodleTLS                      int
	FallbackScsv                   bool
	Freak                          bool
	HasSct                         int
	DhPrimes                       []string
	DhUsesKnownPrimes              int
	DhYsReuse                      bool
	EcdhParameterReuse             bool
	Logjam                         bool
	ChaCha20Preference             bool
	HstsPolicy                     LabsHstsPolicy
	HstsPreloads                   []LabsHstsPreload
	HpkpPolicy                     LabsHpkpPolicy
	HpkpRoPolicy                   LabsHpkpPolicy
	HttpTransactions               []LabsHttpTransaction
	DrownHosts                     []LabsDrownHost
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
	FutureGrade          string
	HasWarnings          bool
	IsExceptional        bool
	Progress             int
	Duration             int
	Eta                  int
	Delegation           int
	Details              LabsEndpointDetails
}

type LabsReport struct {
	Host string
	Port int
	// Reachabel can be "no" if host is not reachable
	// "unknown" if connection isn't tested
	// "http" if only http connection is possible
	// "https" if https connection is possible
	Reachable       string
	Protocol        string
	IsPublic        bool
	Status          string
	StatusMessage   string
	StartTime       int64
	TestTime        int64
	EngineVersion   string
	CriteriaVersion string
	CacheExpiryTime int64
	Endpoints       []LabsEndpoint
	CertHostnames   []string
	Cert            []LabsCert `json:"certs"`
	rawJSON         string

	// HeaderScore holds the results from securityheaders.io
	HeaderScore Securityheaders
	// ObservatoryScan holds the analyzed results from observatory
	ObservatoryScan ObservatoryAnalyzeResult
	// ObservatoryResults holds the raw results
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

// Event holds the information for one specific host that is analyzed
type Event struct {
	host string
	// senderID is a short string which is associated with a specific
	// manager
	senderID  string
	eventType int
	// report holds the scan results
	report *LabsReport
	// tries holds the number of times the event has failed in the current
	// manager. This is used for managing retries
	tries int
	// https holds information if a tls connection can be achieved with
	// the host. Assumed true
	https bool
}

const (
	// FATAL signals that this event is finished and needs to be send directly
	// to SQL if used otherwise they are finished by Control
	FATAL = -3
	// REERROR are errors which need to be retried by the sending manager
	REERROR = -2
	// ERROR are errors that need to be continued by the next manager in line
	ERROR = -1
	// FINISHED signals that the manager finished this event correctly
	FINISHED = 0
)

// eventTypes for the internal channel of the managers
const (
	INTERNAL_ASSESSMENT_FATAL    = -2
	INTERNAL_ASSESSMENT_FAILED   = -1
	INTERNAL_ASSESSMENT_STARTING = 0
	INTERNAL_ASSESSMENT_COMPLETE = 1
)

// HostProvider is a slice of hostnames
type hostProvider struct {
	hostnames   []string
	StartingLen int
}

// newHostProvider creates a hostProvider struct from a slice of hostnames
func newHostProvider(hs []string) *hostProvider {
	hostnames := make([]string, len(hs))
	copy(hostnames, hs)
	hostProvider := hostProvider{hostnames, len(hs)}

	return &hostProvider
}

// next returns the next hostname of hostProvider and true
// if there is none he returns just false
func (hp *hostProvider) next() (string, bool) {
	if len(hp.hostnames) == 0 {

		return "", false
	}
	var e string
	e, hp.hostnames = hp.hostnames[0], hp.hostnames[1:]

	return e, true
}

// Manager defines a unit which is responsible for managing one step in the
// analysis chain. This step is performed concurrently.
type Manager struct {
	// InputEventChannel is a channel for incoming events,
	// that are to be analyzed
	InputEventChannel chan Event
	// OutputEventChannel is a channel for outgoing finished events
	OutputEventChannel chan Event
	// internalEventChannel is a channel which is used for communication
	// with concurrently running analyses
	internalEventChannel chan Event
	// ControlEventChannel is a channel to communicate errors to the Control-Manager
	ControlEventChannel chan Event
	// CloseChannel is a channel which allows one to ask the manager,
	// if there are running analyses
	CloseChannel chan bool
	// logger is a special logger for this manager used for all logging in
	// the manager-context
	logger *log.Logger
}

// NewManager creates a new manager for the given id with the given InputEventChannel and ControlEventChannel.
// In the end the manager is started as an extra goroutine and the created manager is returned.
func NewManager(InputEventChannel chan Event, ControlEventChannel chan Event, id string) *Manager {
	manager := Manager{
		InputEventChannel:    InputEventChannel,
		OutputEventChannel:   make(chan Event),
		internalEventChannel: make(chan Event),
		ControlEventChannel:  ControlEventChannel,
		CloseChannel:         make(chan bool),
	}

	go manager.run(id)

	return &manager
}

// run starts the manager for the step specified by id and also creates the
// corresponding logger. If a new manager is added this needs to be modified.
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

// MasterManager defines a manager that is responsible for building the analysis chain
// and maintaining it. Therefore it is referred to as control.
type MasterManager struct {
	// hostProvider contains all hosts that need to be analyzed
	hostProvider *hostProvider
	// InputEventChannel is a channel which receives events, that passed the
	// analysis chain
	InputEventChannel chan Event
	// OutputEventChannel is the channel through which control sends events
	// to the analysis chain
	OutputEventChannel chan Event
	// ControlEventChannel is used to receive events that failed in a manager
	ControlEventChannel chan Event
	// MainChannel is used to signal main, that the analysis is complete
	MainChannel chan bool
	// useing is a map that defines which steps are used during analysis
	useing map[string]bool
	// results contains the results of all hosts
	results *LabsResults
	// managerList is list of all active managers
	managerList []Manager
	// logger specifies the logger in the control context
	logger *log.Logger
}

// NewMasterManager creates and starts a control manager that starts a analysis chain useing the steps
// defined by useing and analyses the host in hostProvider
func NewMasterManager(hostProvider *hostProvider, useing map[string]bool) *MasterManager {
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

// buildChain builds the manager chain defined  useing in MasterManager
func (manager *MasterManager) buildChain() {
	num := 0
	for _, id := range chain {
		// manager output is the input of the next manager in the chain
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

// handleResults defines what to do with the final results received by control.
// They are appended to the result-list of control
func (manager *MasterManager) handleResult(e Event) {
	manager.results.reports = append(manager.results.reports, *e.report)
	manager.results.responses = append(manager.results.responses, e.report.rawJSON)
}

// checkCloseManager tests if there are events handled by the given manager at
// the moment. If so it returns true
func checkCloseManager(manager Manager) bool {
	select {
	// ask manager
	case manager.CloseChannel <- true:
		select {
		// receive answer
		case b := <-manager.CloseChannel:
			if !b {
				// manager still working: false
				if logLevel >= LOG_DEBUG {
					log.Println("[DEBUG] Manager send 'not finished yet'")
				}
				return false
			}
			// no answer: false
		case <-time.After(time.Millisecond * 500):
			if logLevel >= LOG_DEBUG {
				log.Println("[DEBUG] No Answer received over Close Channel")
			}
			return false
		}
	// not reached: false
	case <-time.After(time.Millisecond * 500):
		if logLevel >= LOG_DEBUG {
			log.Println("[DEBUG] Message couldn't be send over Close Channel")
		}
		return false
	}
	// No more active assessments for manager
	return true
}

// checkClose checks if all managers have finished their work. If so it
// returns true
func (manager *MasterManager) checkClose(errH *ErrorHandler) bool {
	// check every used manager once and the error Handler every time
	// when a manager is checked
	for _, id := range manager.managerList {
		if id == (Manager{}) {
			return true
		}
		if !checkCloseManager(id) {
			if logLevel >= LOG_DEBUG {
				manager.logger.Printf("[DEBUG] Manager with id %s is not finished yet", id.internalEventChannel)
			}
			return false
		}
		if !checkCloseErr(errH) {
			if logLevel >= LOG_DEBUG {
				manager.logger.Println("[DEBUG] Error Handler still has Errors to handle")
			}

			return false
		}
	}
	return true
}

// run starts running the manager
func (manager *MasterManager) run() {
	if logLevel >= LOG_NOTICE {
		manager.logger.Println("[NOTICE] Control-Manager started")
	}
	// starting needed managers and assign their channels
	manager.buildChain()
	if logLevel >= LOG_DEBUG {
		manager.logger.Println("[DEBUG] Manager-chain build successful")
	}

	// creating channelMap for error handler
	var channelMap = make(map[string][2]chan Event, len(chain))
	num := 0
	for _, id := range chain {
		if manager.useing[id] {
			channelMap[id] = [2]chan Event{manager.managerList[num].InputEventChannel,
				manager.managerList[num].OutputEventChannel}
			num = num + 1
		}
	}
	// create channels for the error handler
	var errorChan = make(chan Event)
	var errorQuestionChan = make(chan bool)
	// Starting ErrorHandler for failed entries
	errH := NewErrorHandler(errorChan, errorQuestionChan, channelMap, manager.useing)

	if logLevel >= LOG_DEBUG {
		manager.logger.Println("[DEBUG] ErrorHandler started successful")
	}

	// Input-Channel for Control is the last output channel
	manager.InputEventChannel = manager.managerList[num-1].OutputEventChannel

	// Get first hostEnrty for testing
	host, hasNext := manager.hostProvider.next()

	var e Event
	// create empty Event for host if there is one
	if hasNext {
		e = Event{host, "master", 0, nil, 0, true}
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
		// Stop if there is no host in the list
		if logLevel >= LOG_ERROR {
			manager.logger.Println("[ERROR] The given HostList is empty. Stopping execution")
		}
		close(manager.MainChannel)
		return
	}

	// hasElements is true if there are still events to send for control
	hasElements := true

	// Starting Control-Loop
	if logLevel >= LOG_NOTICE {
		manager.logger.Println("[NOTICE] Starting Control-Loop")
	}
	for {
		// If there are still unsent entries
		if hasElements {
			select {
			case manager.OutputEventChannel <- e:
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] %v is next in line for assessment", e.host)
				}
				// Get next host-entry
				host, hasNext := manager.hostProvider.next()
				if hasNext {
					e = Event{host, "master", 0, nil, 0, true}
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
					// No more hosts in the list
					if logLevel >= LOG_NOTICE {
						manager.logger.Println("[NOTICE] Assessment for all hosts has started")
					}
					hasElements = false
				}
				break
			case cE := <-manager.ControlEventChannel:
				// Handle Messages on the Control-Channel (Errors)
				switch cE.eventType {
				case ERROR:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO] Assessment failed for %v, for the %v. time in %v", e.host, e.tries, e.senderID)
					}
					cE.eventType = FINISHED
					errorChan <- cE
				case REERROR:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO]  %v will be retried in %v", e.host, e.senderID)
					}
					errorChan <- cE
				case FATAL:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO] Fatal Error received for %v from %v", e.host, e.senderID)
					}
					if manager.useing["sql"] {
						if logLevel >= LOG_DEBUG {
							manager.logger.Println("[DEBUG] Sending Fatal Error to ErrorHandler")
						}
						errorChan <- cE
					} else {
						if logLevel >= LOG_DEBUG {
							manager.logger.Println("[DEBUG] Finishing Fatal Error")
						}
						manager.handleResult(cE)
					}
				}
				break
			case iE := <-manager.InputEventChannel:
				// Handle incoming results
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
			// same as before but with no more sending. Instead checking if analysis is finished
			select {
			case cE := <-manager.ControlEventChannel:
				// Handle Messages on the Control-Channel
				switch cE.eventType {
				case ERROR:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO] Assessment failed for %v, for the %v. time in %v", e.host, e.tries, e.senderID)
					}
					cE.eventType = FINISHED
					errorChan <- cE
				case REERROR:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO]  %v will be retried in %v", e.host, e.senderID)
					}
					errorChan <- cE
				case FATAL:
					if logLevel >= LOG_INFO {
						manager.logger.Printf("[INFO] Fatal Error received for %v from %v", e.host, e.senderID)
					}
					if manager.useing["sql"] {
						if logLevel >= LOG_DEBUG {
							manager.logger.Println("[DEBUG] Sending Fatal Error to ErrorHandler")
						}
						errorChan <- cE
					} else {
						if logLevel >= LOG_DEBUG {
							manager.logger.Println("[DEBUG] Finishing Fatal Error")
						}
						manager.handleResult(cE)
					}

				}
				break
			case iE := <-manager.InputEventChannel:
				// Handle incoming results
				if logLevel >= LOG_INFO {
					manager.logger.Printf("[INFO] Results for %v received", e.host)
				}
				manager.handleResult(iE)
				if logLevel >= LOG_DEBUG {
					manager.logger.Printf("[DEBUG] Results for %v have been handled", e.host)
				}
				break
			case <-time.After(time.Millisecond * 2000):
				// Check if there is no more manager or error handler running
				if logLevel >= LOG_DEBUG {
					manager.logger.Println("[DEBUG] Checking if scan is finished!")
				}
				if manager.checkClose(errH) {
					if logLevel >= LOG_NOTICE {
						manager.logger.Println("[NOTICE] Scan complete")
					}
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

// parseLogLevel returns the loglevel corresponding to a string
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

// readLines reads all lines of a file. Returning a slice with all the lines
func readLines(path *string) ([]string, error) {
	// open File
	file, err := os.Open(*path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	br := bufio.NewReader(file)
	// read the byte order marking, if it exists
	r, _, err := br.ReadRune()
	if err != nil {
		log.Fatalf("[ERROR] Failed reading Byte Order Marking: %v", err.Error())
	}
	if r != '\uFEFF' {
		br.UnreadRune()
	}
	// start reading lines
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
	}

	return true

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
	var conf_verbosity = flag.String("verbosity", "info", "Configure log verbosity: error, notice, info, debug, or trace.")
	var conf_version = flag.Bool("version", false, "Print version and API location information and exit")

	//Added Flags
	var conf_securityheaders = flag.Bool("no-securityheaders", false, "Don't include a scan for security headers")
	var conf_sql_retries = flag.Int("sql-retries", 3, "Number of retries if the SQL-connection fails")
	var conf_observatory = flag.Bool("no-observatory", false, "Don't include a scan using the mozilla observatory API")
	var conf_ssllabs = flag.Bool("no-ssllabs", false, "Don't use SSLlabs-Scan")
	var conf_ssltest = flag.Bool("no-ssltest", false, "Don't test hosts before starting Scan")
	var conf_sql = flag.Bool("no-sql", false, "Don't write results into the database")
	var conf_sslTries = flag.Int("sslTest-retries", 1, "Number of retries if the sslTest fails")
	var conf_labsTries = flag.Int("labs-retries", 0, "Number of retries if the sslLabs-Scan fails")
	var conf_obsTries = flag.Int("obs-retries", 1, "Number of retries if the Observatory-Scan fails")
	var conf_secHTries = flag.Int("secH-retries", 2, "Number of retries if the Securityheader-Scan fails")
	var conf_maxAssessments = flag.Float64("maxFactor", 1.0, "Relative Auslastung von MaxAssessments")

	flag.Parse()

	// Setup according to flags

	// Setting max retries for all managers
	sslTries = *conf_sslTries + 1
	obsTries = *conf_obsTries + 1
	labsTries = *conf_labsTries + 1
	secHTries = *conf_secHTries + 1

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

	if *conf_maxAssessments > 1.0 {
		faktor = 1.0
	} else {
		faktor = *conf_maxAssessments
	}

	globalSQLRetries = *conf_sql_retries

	// sql needs to know if observatory is used
	if !*conf_observatory {
		globalObservatory = true
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

	// set the steps to be used
	var useing = map[string]bool{"labs": !*conf_ssllabs, "obs": !*conf_observatory, "secH": !*conf_securityheaders, "sql": !*conf_sql, "ssl": !*conf_ssltest}

	// create files and directories for logging output and results
	err := os.Mkdir("log", 0700)
	if err != nil && os.IsNotExist(err) {
		log.Fatalf("[FATAL] Could not create loggingFolder log: %v", err.Error())
	}

	err = os.Mkdir("results", 0700)
	if err != nil && os.IsNotExist(err) {
		log.Fatalf("[FATAL] Could not create resultFolder res: %v", err.Error())
	}

	// files are named after this date-time schema
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

	// create HostProvider containing the host that need to be analyzed
	hp := newHostProvider(hostnames)

	// start analysis by starting control
	manager := NewMasterManager(hp, useing)

	// Respond to events until all the work is done.
	for {
		_, running := <-manager.MainChannel
		// print results to file and show elapsed time
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
