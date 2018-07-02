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

// work in progress
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

	"github.com/fatih/structs"
)

var sslLabsManager = Manager{
	3,  //Max Retries
	10, //Max parallel Scans
	labsVersion,
	"SSLLabs",              //Table name
	scanOnlySSL,            // Scan HTTP and HTTPS
	nil,                    //output channel
	logDebug,               //loglevel
	scanStatus{0, 0, 0, 0}, // initial scanStatus
	0,                   // number of errors while finishing
	0,                   // scanID
	[]internalMessage{}, //errors
	false,               //has not started first scan
}

var USER_AGENT = "ssllabs-scan v1.5.0 (dev $Id$)"

// How many assessment do we have in progress?
var LabsActiveAssessments = 0

// How many assessments does the server think we have in progress?
var LabsCurrentAssessments = -1

// The maximum number of assessments we can have in progress at any one time.
var LabsMaxAssessments = -1

var LabsRequestCounter uint64 = 0

var LabsApiLocation = "https://api.ssllabs.com/api/v3"

var LabsNewAssessmentCoolOff int64 = 1100

var LabsIgnoreMismatch = true

var LabsStartNew = true

var LabsFromCache = false

var LabsMaxAge = 0

var LabsInsecure = false

var LabsHttpClient *http.Client

var LabsLastTime time.Time

var labsVersion = "10"

var CertificatesTable = "CertificatesV10"

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

type CertificateRow struct {
	Thumbprint       string
	ID               string
	SerialNumber     string
	Subject          string
	Issuer           string
	SigAlg           string
	RevocationStatus uint8
	Issues           int16
	KeyStrength      int16
	DebianInsecure   bool
	NotBefore        int64
	NotAfter         int64
	NextThumbprint   string
}

type SSLLabsTableRow struct {
	IP                        string
	StartTime                 int64
	TestTime                  int64
	Grade                     string
	GradeTrustIgnored         string
	FutureGrade               string
	HasWarnings               bool
	IsExceptional             bool
	NumberWeakProtocols       int
	WeakProtocols             string
	NumberProtocols           int
	Protocols                 string
	NumberWeakSuites          int
	WeakSuites                string
	NumberSuites              int
	Suites                    string
	ForwardSecrecy            uint8
	RenegSupport              uint8
	SupportsRC4               bool
	VulnBeast                 bool
	VulnHeartbleed            bool
	VulnOpenSslCcs            int16
	VulnOpenSSLLuckyMinus20   int16
	VulnTicketbleed           uint8
	VulnBleichenbacher        int16
	VulnPoodle                uint8
	VulnFreak                 bool
	VulnLogjam                bool
	VulnDrown                 bool
	DhUsesKnownPrimes         uint8
	DhYsReuse                 bool
	EcdhParameterReuse        bool
	CertificateChainIssues    int16
	CertificateChainLength    uint8
	BaseCertificateThumbprint string
	ScanStatus                int
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
	SerialNumber           string
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
	Q                *int
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
	Q              *int
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
	Host            string
	Port            int
	Protocol        string
	IsPublic        bool
	Status          string
	StatusMessage   string
	StartTime       int64
	TestTime        int64
	EngineVersion   string
	CriteriaVersion string
	CacheExpiryTime int64
	CertHostnames   []string
	Endpoints       []LabsEndpoint
	Certs           []LabsCert
	rawJSON         string
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

func invokeGetRepeatedly(url string) (*http.Response, []byte, error) {
	retryCount := 0

	for {
		var reqId = atomic.AddUint64(&LabsRequestCounter, 1)

		if logLevel >= logDebug {
			log.Printf("[DEBUG] Request #%v: %v", reqId, url)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Add("User-Agent", USER_AGENT)

		resp, err := LabsHttpClient.Do(req)
		if err == nil {
			if logLevel >= logDebug {
				log.Printf("[DEBUG] Response #%v status: %v %v", reqId, resp.Proto, resp.Status)
			}

			if logLevel >= logTrace {
				for key, values := range resp.Header {
					for _, value := range values {
						log.Printf("[TRACE] %v: %v\n", key, value)
					}
				}
			}

			if logLevel >= logNotice {
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
					if LabsCurrentAssessments != i {
						LabsCurrentAssessments = i

						if logLevel >= logDebug {
							log.Printf("[DEBUG] Server set current assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= logWarning {
						log.Printf("[WARNING] Ignoring invalid X-Current-Assessments value (%v): %v", headerValue, err)
					}
				}
			}

			// Update maximum assessments.

			headerValue = resp.Header.Get("X-Max-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if LabsMaxAssessments != i {
						LabsMaxAssessments = i

						if LabsMaxAssessments <= 0 {
							log.Fatalf("[ERROR] Server doesn't allow further API requests")
						}

						if logLevel >= logDebug {
							log.Printf("[DEBUG] Server set maximum assessments to %v", headerValue)
						}
					}
				} else {
					if logLevel >= logWarning {
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

			if logLevel >= logTrace {
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

				if logLevel >= logDebug {
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
	var url = LabsApiLocation + "/" + command

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

			sleepTime := 60 + rand.Int31n(60)

			if logLevel >= logNotice {
				log.Printf("[NOTICE] Sleeping for %v Seconds after a %v response", sleepTime, resp.StatusCode)
			}

			time.Sleep(time.Duration(sleepTime) * time.Second)
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

		if LabsMaxAge != 0 {
			command = command + "&maxAge=" + strconv.Itoa(LabsMaxAge)
		}
	} else if startNew {
		command = command + "&startNew=on"
	}

	if LabsIgnoreMismatch {
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

func (manager *Manager) labsAssessment(scan internalMessage, internalChannel chan internalMessage) {
	var report *LabsReport
	var startTime int64 = -1
	var startNew = LabsStartNew

	for {
		myResponse, err := invokeAnalyze(scan.domain.DomainName, startNew, LabsFromCache)
		if err != nil {
			// TODO handle errors better
			scan.statusCode = statusError
			internalChannel <- scan
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
				// TODO handle errors better
				scan.statusCode = statusError
				internalChannel <- scan
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
	scan.results = report
	scan.statusCode = statusDone
	internalChannel <- scan
}

func (manager *Manager) labsRun() error {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: LabsInsecure},
		DisableKeepAlives: false,
		Proxy:             http.ProxyFromEnvironment,
	}

	LabsHttpClient = &http.Client{Transport: transport}

	// Ping SSL Labs to determine how many concurrent
	// assessments we're allowed to use. Print the API version
	// information and the limits.

	labsInfo, err := invokeInfo()
	if err != nil {
		// TODO Handle Error
		return err
	}

	if logLevel >= logInfo {
		log.Printf("[INFO] SSL Labs v%v (criteria version %v)", labsInfo.EngineVersion, labsInfo.CriteriaVersion)
	}

	if logLevel >= logNotice {
		for _, message := range labsInfo.Messages {
			log.Printf("[NOTICE] Server message: %v", message)
		}
	}

	LabsMaxAssessments = labsInfo.MaxAssessments

	if LabsMaxAssessments <= 0 {
		if logLevel >= logWarning {
			log.Printf("[WARNING] You're not allowed to request new assessments")
		}
	}

	if labsInfo.NewAssessmentCoolOff >= 1000 {
		LabsNewAssessmentCoolOff = 100 + labsInfo.NewAssessmentCoolOff
	} else {
		if logLevel >= logWarning {
			log.Printf("[WARNING] Info.NewAssessmentCoolOff too small: %v", labsInfo.NewAssessmentCoolOff)
		}
	}
	LabsLastTime = time.Now()
	return nil
}

func (manager *Manager) labsHandleScan(domains []DomainsReachable, internalChannel chan internalMessage) []DomainsReachable {
	for len(domains) > 0 && LabsCurrentAssessments < LabsMaxAssessments && time.Since(LabsLastTime) > time.Duration(LabsNewAssessmentCoolOff)*time.Millisecond {
		// pop fist domain
		manager.firstScan = true
		LabsLastTime = time.Now()
		scan, retDom := domains[0], domains[1:]
		scanMsg := internalMessage{scan, nil, 0, internalNew}
		go manager.labsAssessment(scanMsg, internalChannel)
		manager.status.addCurrentScans(1)
		return retDom
	}
	return domains
}

func (manager *Manager) labsHandleResults(result internalMessage) {
	manager.status.addCurrentScans(-1)
	res, ok := result.results.(*LabsReport)
	if !ok {
		//TODO Handle Error
		log.Print("SSLLabs manager couldn't assert type")
		res = &LabsReport{}
		result.statusCode = internalFatalError
	}

	labsRes := makeSSLLabsRow(res)

	switch result.statusCode {
	case internalFatalError:
		// TODO Handle Error
		labsRes.ScanStatus = statusError
		manager.status.addErrorScans(1)
	case internalSuccess:
		// TODO Handle Success
		labsRes.ScanStatus = statusDone
		manager.status.addFinishedScans(1)
	}
	where := ScanWhereCond{result.domain.DomainID, manager.scanID, result.domain.TestWithSSL}
	err := saveResults(manager.getTableName(), structs.New(where), structs.New(labsRes))
	if err != nil {
		//TODO Handle Error
		log.Printf("SSLLabs couldn't save results for %s: %s", result.domain.DomainName, err.Error())
		return
	}
	certRows := makeCertificateRows(res)
	err = saveCertificates(certRows, CertificatesTable)
	if err != nil {
		//TODO Handle Error
		log.Printf("SSLLabs couldn't save certificates for %s: %s", result.domain.DomainName, err.Error())
		return
	}
}

func makeCertificateRows(report *LabsReport) []*CertificateRow {
	var res = []*CertificateRow{}
	var chainLength = len(report.Certs)
	if len(report.Endpoints) == 0 {
		//TODO ERROR HANDLING
		fmt.Println("No Endpoints in the report!")
		return res
	}
	for i, cert := range report.Certs {
		row := &CertificateRow{}
		row.Thumbprint = truncate(cert.Sha1Hash, 40)
		row.ID = truncate(cert.Id, 80)
		row.SerialNumber = truncate(cert.SerialNumber, 100)
		row.Subject = truncate(cert.Subject, 300)
		row.Issuer = truncate(cert.IssuerSubject, 300)
		row.SigAlg = truncate(cert.SigAlg, 30)
		row.RevocationStatus = uint8(cert.RevocationStatus)
		row.Issues = int16(cert.Issues)
		row.KeyStrength = int16(cert.KeyStrength)
		row.DebianInsecure = cert.KeyKnownDebianInsecure
		row.NotAfter = cert.NotAfter
		row.NotBefore = cert.NotBefore
		if i+1 < chainLength {
			row.NextThumbprint = truncate(report.Certs[i+1].Sha1Hash, 40)
		}

		res = append(res, row)
	}
	return res
}

func makeSSLLabsRow(report *LabsReport) *SSLLabsTableRow {
	var helpInt int
	var helpStr string
	if len(report.Endpoints) == 0 {
		//TODO ERROR HANDLING
		fmt.Sprintln("No Endpoints in the report!")
		return &SSLLabsTableRow{}
	}
	endpoint := report.Endpoints[0]
	details := endpoint.Details
	row := &SSLLabsTableRow{}
	row.IP = truncate(endpoint.IpAddress, 15)
	row.StartTime = report.StartTime
	row.TestTime = report.TestTime
	row.Grade = truncate(endpoint.Grade, 2)
	row.GradeTrustIgnored = truncate(endpoint.GradeTrustIgnored, 2)
	row.FutureGrade = truncate(endpoint.FutureGrade, 2)
	row.HasWarnings = endpoint.HasWarnings
	row.IsExceptional = endpoint.IsExceptional

	helpStr, helpInt = getProtocols(details, true)
	row.NumberWeakProtocols = helpInt
	row.WeakProtocols = truncate(helpStr, 50)

	helpStr, helpInt = getProtocols(details, false)
	row.NumberProtocols = helpInt
	row.Protocols = truncate(helpStr, 50)

	helpStr, helpInt = getSuites(details, true)
	row.NumberWeakSuites = helpInt
	row.WeakSuites = truncate(helpStr, 2000)

	helpStr, helpInt = getSuites(details, false)
	row.NumberSuites = helpInt
	row.Suites = truncate(helpStr, 4000)

	row.ForwardSecrecy = uint8(details.ForwardSecrecy)
	row.RenegSupport = uint8(details.RenegSupport)
	row.SupportsRC4 = details.SupportsRc4
	row.VulnBeast = details.VulnBeast
	row.VulnHeartbleed = details.Heartbleed
	row.VulnOpenSslCcs = int16(details.OpenSslCcs)
	row.VulnOpenSSLLuckyMinus20 = int16(details.OpenSSLLuckyMinus20)
	row.VulnTicketbleed = uint8(details.Ticketbleed)
	row.VulnBleichenbacher = int16(details.Bleichenbacher)
	row.VulnPoodle = uint8(details.PoodleTLS)
	row.VulnFreak = details.Freak
	row.VulnLogjam = details.Logjam
	row.VulnDrown = details.DrownVulnerable
	row.DhUsesKnownPrimes = uint8(details.DhUsesKnownPrimes)
	row.DhYsReuse = details.DhYsReuse
	row.EcdhParameterReuse = details.EcdhParameterReuse
	if len(details.CertChains) != 0 {
		row.CertificateChainIssues = int16(details.CertChains[0].Issues)
		row.CertificateChainLength = uint8(len(details.CertChains[0].CertIds))
	}
	if len(report.Certs) != 0 {
		row.BaseCertificateThumbprint = truncate(report.Certs[0].Sha1Hash, 40)
	}

	return row

}

func getProtocols(details LabsEndpointDetails, weak bool) (string, int) {
	var str []string
	var i int
	for _, protocol := range details.Protocols {
		if protocol.Q != nil || !weak {
			str = append(str, protocol.Name+protocol.Version)
			i++
		}
	}
	return strings.Join(str, ", "), i
}

func getSuites(details LabsEndpointDetails, weak bool) (string, int) {
	var str []string
	var str2 []string
	var i int
	var prot2string = map[int]string{
		0x0300: "SSL 3.0",
		0x0301: "TLS 1.0",
		0x0302: "TLS 1.1",
		0x0303: "TLS 1.2",
		0x0304: "TLS 1.3",
	}
	for _, suites := range details.Suites {
		for _, suite := range suites.List {
			if suite.Q != nil || !weak {
				i++
				str2 = append(str2, fmt.Sprintf("%s", suite.Name))
			}
		}
		if len(str2) != 0 {
			str = append(str, fmt.Sprintf("%s: %s", prot2string[suites.Protocol], strings.Join(str2, ", ")))
		}
		str2 = []string{}
	}
	return strings.Join(str, "; "), i
}
