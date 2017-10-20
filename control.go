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
}

const (
	ERROR        = -1
	FINISHED     = 0
	OUTPUT_CLOSE = 1
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

func (hp *HostProvider) retry(host string) {
	hp.hostnames = append(hp.hostnames, host)
}

type Manager struct {
	InputEventChannel    chan Event
	OutputEventChannel   chan Event
	InternalEventChannel chan Event
	ControlEventChannel  chan Event
}

func NewManager(InputEventChannel chan Event, ControlEventChannel chan Event, id string) *Manager {
	manager := Manager{
		InputEventChannel:    InputEventChannel,
		OutputEventChannel:   make(chan Event),
		InternalEventChannel: make(chan Event),
		ControlEventChannel:  ControlEventChannel,
	}

	go manager.run(id)

	return &manager
}

func (manager *Manager) finish(id string) {
	var closeEvent = Event{
		host:      "none",
		senderID:  id,
		eventType: OUTPUT_CLOSE,
		report:    nil,
	}
	manager.ControlEventChannel <- closeEvent
	return
}

func (manager *Manager) run(id string) error {
	switch {
	case id == "ssl":
		manager.sslRun()
		break
	case id == "labs":
		manager.labsRun()
		break
	case id == "obs":
		manager.obsRun()
		break
	case id == "secH":
		manager.secHRun()
		break
	case id == "sql":
		manager.sqlRun()
		break
	default:
		return fmt.Errorf("undefined manager.run id: %v", id)
	}
	return nil
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
			if logLevel >= LOG_DEBUG {
				log.Printf("[DEBUG] Manager %v started in place %v", id, num)
			}

			num = num + 1
		}

	}
}

func (manager *MasterManager) handleResult(e Event) {
	manager.results.reports = append(manager.results.reports, *e.report)
	manager.results.responses = append(manager.results.responses, e.report.rawJSON)
}

func (manager *MasterManager) run() {
	manager.buildChain()
	channelMap := make(map[string]chan Event)
	num := 0
	for _, id := range chain {
		if manager.useing[id] {
			channelMap[id] = manager.managerList[num].OutputEventChannel
			num = num + 1
		}
	}
	manager.InputEventChannel = manager.managerList[num-1].OutputEventChannel
	//manager: ssl(falls da, immer manager[0]) labs obs secH sql
	//bool Manager: useSsl useLabs useObs useSecH useSql {map}
	host, hasNext := manager.hostProvider.next()
	var e Event
	if hasNext {
		e = Event{host, "master", 0, nil}
	} else {
		close(manager.InputEventChannel)
		close(manager.ControlEventChannel)
		return
	}
	hasElements := true
	for {
		if hasElements {
			select {
			// Handle assessment events (e.g., starting and finishing).
			case manager.OutputEventChannel <- e:
				log.Printf("Event for host %v send", e.host)
				host, hasNext := manager.hostProvider.next()
				if hasNext {
					e = Event{host, "master", 0, nil}
				} else {
					hasElements = false
					close(manager.OutputEventChannel)
				}
				break
			case cE := <-manager.ControlEventChannel:
				switch cE.eventType {
				case OUTPUT_CLOSE:
					close(channelMap[cE.senderID])
					break
				case ERROR:
					if cE.senderID == "ssl" {
						cE.eventType = FINISHED
						if manager.useing["labs"] {
							channelMap["labs"] <- cE
						} else {
							channelMap["ssl"] <- cE
						}
					} else {
						log.Printf("[ERROR] Host %v failed in %v", e.host, e.senderID)
						//manager.handleError(e) //TODO
						break
					}
				}
				break
			case iE, ok := <-manager.InputEventChannel:
				if !ok {
					close(manager.ControlEventChannel)
					return
				}
				manager.handleResult(iE)
				break
			default:
				<-time.NewTimer(time.Duration(100) * time.Millisecond).C
				break
			}
		} else {
			select {
			case cE := <-manager.ControlEventChannel:
				switch cE.eventType {
				case OUTPUT_CLOSE:
					close(channelMap[cE.senderID])
					break
				case ERROR:
					switch cE.senderID {
					case "ssl":
						cE.eventType = FINISHED
						if manager.useing["labs"] {
							channelMap["labs"] <- cE
						} else {
							channelMap["ssl"] <- cE
						}
						break
					case "obs":
						cE.eventType = FINISHED
						channelMap["obs"] <- cE
						break
					case "secH":
						cE.eventType = FINISHED
						channelMap["secH"] <- cE
					default:
						log.Printf("[ERROR] Host %v ultimately failed in %v", e.host, e.senderID)
						//manager.handleError(e) //TODO
						break
					}

				}
				break
			case iE, ok := <-manager.InputEventChannel:
				if !ok {
					close(manager.MainChannel)
					return
				}
				manager.handleResult(iE)
				break
			default:
				<-time.NewTimer(time.Duration(5000) * time.Millisecond).C
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
	var conf_verbosity = flag.String("verbosity", "info", "Configure log verbosity: error, notice, info, debug, or trace.")
	var conf_version = flag.Bool("version", false, "Print version and API location information and exit")

	var conf_securityheaders = flag.Bool("securityheaders", false, "Include a scan for security headers")
	var conf_sql_retries = flag.Int("sql-retries", 3, "Number of retries if the SQL-connection fails")
	var conf_observatory = flag.Bool("observatory", false, "Include a scan using the mozilla observatory API")

	flag.Parse()

	globalSQLRetries = *conf_sql_retries

	if *conf_observatory {
		globalObservatory = true
	}

	if *conf_securityheaders {
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

	hp := NewHostProvider(hostnames)
	manager := NewMasterManager(hp, map[string]bool{"labs": true, "obs": true, "secH": true, "sql": true, "ssl": true})

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
						fmt.Println(name + ": " + grade)
					}
				}
			} else if *conf_json_flat {
				// Flat JSON and RAW

				for i := range manager.results.responses {
					results := []byte(manager.results.responses[i])

					flattened := flattenAndFormatJSON(results)

					// Print the flattened data
					fmt.Println(*flattened)
				}
			} else {
				// Raw (non-Go-mangled) JSON output

				fmt.Println("[")
				for i := range manager.results.responses {
					results := manager.results.responses[i]

					if i > 0 {
						fmt.Println(",")
					}
					fmt.Println(results)
				}
				fmt.Println("]")
			}

			if err != nil {
				log.Fatalf("[ERROR] Output to JSON failed: %v", err)
			}

			fmt.Println(string(results))

			if logLevel >= LOG_INFO {
				log.Println("[INFO] All assessments complete; shutting down")
			}
			elapsed := time.Since(startTime)
			log.Printf("It took %s", elapsed)
			return
		}
	}
}
