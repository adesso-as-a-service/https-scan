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

package ssllabs

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"../../backend"
	"../../hooks"
	"github.com/fatih/structs"
)

var maxScans = 10

var used *bool

// crawlerVersion
var version = "10"

var maxRetries *int

// crawlerManager
var manager = hooks.Manager{
	MaxRetries:       3,        //Max Retries
	MaxParallelScans: maxScans, //Max parallel Scans
	Version:          version,
	Table:            "SSLLabs",                 //Table name
	ScanType:         hooks.ScanOnlySSL,         // Scan HTTP or HTTPS
	OutputChannel:    nil,                       //output channel
	LogLevel:         hooks.LogNotice,           //loglevel
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
}

var USER_AGENT = "ssllabs-scan v1.5.0 (dev $Id$)"

// How many assessments does the server think we have in progress?
var currentAssessments = -1

// The maximum number of assessments we can have in progress at any one time.
var maxAssessments = -1

var requestCounter uint64

var APILocation = "https://api.ssllabs.com/api/v3"

var newAssessmentCoolOff int64 = 1100

var ignoreMismatch = true

var startNew = true

var fromCache = false

var maxAge = 0

var insecure = false

var httpClient *http.Client

var lastTime time.Time

var certificatesTable = "CertificatesV10"

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

type TableRow struct {
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
		var reqId = atomic.AddUint64(&requestCounter, 1)

		if manager.LogLevel >= hooks.LogDebug {
			log.Printf("[DEBUG] Request #%v: %v", reqId, url)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Add("User-Agent", USER_AGENT)

		resp, err := httpClient.Do(req)
		if err == nil {
			if manager.LogLevel >= hooks.LogDebug {
				log.Printf("[DEBUG] Response #%v status: %v %v", reqId, resp.Proto, resp.Status)
			}

			if manager.LogLevel >= hooks.LogTrace {
				for key, values := range resp.Header {
					for _, value := range values {
						log.Printf("[TRACE] %v: %v\n", key, value)
					}
				}
			}

			if manager.LogLevel >= hooks.LogNotice {
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
					if currentAssessments != i {
						currentAssessments = i

						if manager.LogLevel >= hooks.LogDebug {
							log.Printf("[DEBUG] Server set current assessments to %v", headerValue)
						}
					}
				} else {
					if manager.LogLevel >= hooks.LogWarning {
						log.Printf("[WARNING] Ignoring invalid X-Current-Assessments value (%v): %v", headerValue, err)
					}
				}
			}

			// Update maximum assessments.

			headerValue = resp.Header.Get("X-Max-Assessments")
			if headerValue != "" {
				i, err := strconv.Atoi(headerValue)
				if err == nil {
					if maxAssessments != i {
						maxAssessments = i

						if maxAssessments <= 0 {
							log.Fatalf("[ERROR] Server doesn't allow further API requests")
						}

						if manager.LogLevel >= hooks.LogDebug {
							log.Printf("[DEBUG] Server set maximum assessments to %v", headerValue)
						}
					}
				} else {
					if manager.LogLevel >= hooks.LogWarning {
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

			if manager.LogLevel >= hooks.LogTrace {
				log.Printf("[TRACE] Response #%v body:\n%v", reqId, string(body))
			}

			return resp, body, nil
		}

		if strings.Contains(err.Error(), "EOF") {
			// Server closed a persistent connection on us, which
			// Go doesn't seem to be handling well. So we'll try one
			// more time.
			if retryCount > 5 {
				log.Fatalf("[ERROR] Too many HTTP requests (5) failed with EOF (ref#2)")
			}

			if manager.LogLevel >= hooks.LogDebug {
				log.Printf("[DEBUG] HTTP request failed with EOF (ref#2)")
			}
		} else {
			log.Fatalf("[ERROR] HTTP request failed: %v (ref#2)", err.Error())
		}

		retryCount++

	}
}

func invokeApi(command string) (*http.Response, []byte, error) {
	var url = APILocation + "/" + command

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

			if manager.LogLevel >= hooks.LogNotice {
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

		if maxAge != 0 {
			command = command + "&maxAge=" + strconv.Itoa(maxAge)
		}
	} else if startNew {
		command = command + "&startNew=on"
	}

	if ignoreMismatch {
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
	}
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

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {
	var report *LabsReport
	var startTime int64 = -1
	var startNew = startNew

	for {
		myResponse, err := invokeAnalyze(scan.Domain.DomainName, startNew, fromCache)
		if err != nil {
			// TODO handle errors better
			scan.StatusCode = hooks.StatusError
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
				scan.StatusCode = hooks.StatusError
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
	scan.Results = report
	scan.StatusCode = hooks.StatusDone
	internalChannel <- scan
}

func run() error {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
		DisableKeepAlives: false,
		Proxy:             http.ProxyFromEnvironment,
	}

	httpClient = &http.Client{Transport: transport}

	// Ping SSL Labs to determine how many concurrent
	// assessments we're allowed to use. Print the API version
	// information and the limits.

	labsInfo, err := invokeInfo()
	if err != nil {
		// TODO Handle Error
		return err
	}

	if manager.LogLevel >= hooks.LogInfo {
		log.Printf("[INFO] SSL Labs v%v (criteria version %v)", labsInfo.EngineVersion, labsInfo.CriteriaVersion)
	}

	if manager.LogLevel >= hooks.LogNotice {
		for _, message := range labsInfo.Messages {
			log.Printf("[NOTICE] Server message: %v", message)
		}
	}

	maxAssessments = labsInfo.MaxAssessments

	if maxAssessments <= 0 {
		if manager.LogLevel >= hooks.LogWarning {
			log.Printf("[WARNING] You're not allowed to request new assessments")
		}
	}

	if labsInfo.NewAssessmentCoolOff >= 1000 {
		newAssessmentCoolOff = 100 + labsInfo.NewAssessmentCoolOff
	} else {
		if manager.LogLevel >= hooks.LogWarning {
			log.Printf("[WARNING] Info.NewAssessmentCoolOff too small: %v", labsInfo.NewAssessmentCoolOff)
		}
	}
	lastTime = time.Now()
	return nil
}

func handleScan(domains []hooks.DomainsReachable, internalChannel chan hooks.InternalMessage) []hooks.DomainsReachable {
	for len(domains) > 0 && currentAssessments < maxAssessments && time.Since(lastTime) > time.Duration(newAssessmentCoolOff)*time.Millisecond {
		// pop fist domain
		manager.FirstScan = true
		lastTime = time.Now()
		scan, retDom := domains[0], domains[1:]
		scanMsg := hooks.InternalMessage{
			Domain:     scan,
			Results:    nil,
			Retries:    0,
			StatusCode: hooks.InternalNew,
		}
		go assessment(scanMsg, internalChannel)
		manager.Status.AddCurrentScans(1)
		return retDom
	}
	return domains
}

func handleResults(result hooks.InternalMessage) {
	manager.Status.AddCurrentScans(-1)
	res, ok := result.Results.(*LabsReport)
	if !ok {
		//TODO Handle Error
		log.Print("SSLLabs manager couldn't assert type")
		res = &LabsReport{}
		result.StatusCode = hooks.InternalFatalError
	}

	labsRes := makeSSLLabsRow(res)

	switch result.StatusCode {
	case hooks.InternalFatalError:
		// TODO Handle Error
		labsRes.ScanStatus = hooks.StatusError
		manager.Status.AddErrorScans(1)
	case hooks.InternalSuccess:
		// TODO Handle Success
		labsRes.ScanStatus = hooks.StatusDone
		manager.Status.AddFinishedScans(1)
	}

	certRows := makeCertificateRows(res)
	err := backend.SaveCertificates(certRows, certificatesTable)
	if err != nil {
		//TODO Handle Error
		log.Printf("SSLLabs couldn't save certificates for %s: %s", result.Domain.DomainName, err.Error())
		return
	}

	where := hooks.ScanWhereCond{
		DomainID:    result.Domain.DomainID,
		ScanID:      manager.ScanID,
		TestWithSSL: result.Domain.TestWithSSL}
	err = backend.SaveResults(manager.GetTableName(), structs.New(where), structs.New(labsRes))
	if err != nil {
		//TODO Handle Error
		log.Printf("SSLLabs couldn't save results for %s: %s", result.Domain.DomainName, err.Error())
		return
	}

}

func makeCertificateRows(report *LabsReport) []*hooks.CertificateRow {
	var res = []*hooks.CertificateRow{}
	var chainLength = len(report.Certs)
	if len(report.Endpoints) == 0 {
		//TODO ERROR HANDLING
		fmt.Println("No Endpoints in the report!")
		return res
	}
	for i, cert := range report.Certs {
		row := &hooks.CertificateRow{}
		row.Thumbprint = hooks.Truncate(cert.Sha1Hash, 40)
		row.ID = hooks.Truncate(cert.Id, 80)
		row.SerialNumber = hooks.Truncate(cert.SerialNumber, 100)
		row.Subject = hooks.Truncate(cert.Subject, 300)
		row.Issuer = hooks.Truncate(cert.IssuerSubject, 300)
		row.SigAlg = hooks.Truncate(cert.SigAlg, 30)
		row.RevocationStatus = uint8(cert.RevocationStatus)
		row.Issues = int16(cert.Issues)
		row.KeyStrength = int16(cert.KeyStrength)
		row.DebianInsecure = cert.KeyKnownDebianInsecure
		row.NotAfter = cert.NotAfter
		row.NotBefore = cert.NotBefore
		if i+1 < chainLength {
			row.NextThumbprint = sql.NullString{
				String: hooks.Truncate(report.Certs[i+1].Sha1Hash, 40),
				Valid:  true,
			}
		}

		res = append([]*hooks.CertificateRow{row}, res...)
	}
	return res
}

func makeSSLLabsRow(report *LabsReport) *TableRow {
	var helpInt int
	var helpStr string
	if len(report.Endpoints) == 0 {
		//TODO ERROR HANDLING
		fmt.Sprintln("No Endpoints in the report!")
		return &TableRow{}
	}
	endpoint := report.Endpoints[0]
	details := endpoint.Details
	row := &TableRow{}
	row.IP = hooks.Truncate(endpoint.IpAddress, 15)
	row.StartTime = report.StartTime
	row.TestTime = report.TestTime
	row.Grade = hooks.Truncate(endpoint.Grade, 2)
	row.GradeTrustIgnored = hooks.Truncate(endpoint.GradeTrustIgnored, 2)
	row.FutureGrade = hooks.Truncate(endpoint.FutureGrade, 2)
	row.HasWarnings = endpoint.HasWarnings
	row.IsExceptional = endpoint.IsExceptional

	helpStr, helpInt = getProtocols(details, true)
	row.NumberWeakProtocols = helpInt
	row.WeakProtocols = hooks.Truncate(helpStr, 50)

	helpStr, helpInt = getProtocols(details, false)
	row.NumberProtocols = helpInt
	row.Protocols = hooks.Truncate(helpStr, 50)

	helpStr, helpInt = getSuites(details, true)
	row.NumberWeakSuites = helpInt
	row.WeakSuites = hooks.Truncate(helpStr, 2000)

	helpStr, helpInt = getSuites(details, false)
	row.NumberSuites = helpInt
	row.Suites = hooks.Truncate(helpStr, 4000)

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
		row.BaseCertificateThumbprint = hooks.Truncate(report.Certs[0].Sha1Hash, 40)
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

func flagSetUp() {
	used = flag.Bool("no-ssllabs", false, "Don't use the SSLLabs-Scan")
	maxRetries = flag.Int("labs-retries", 1, "Number of retries for the sslLabs-Scan")
}

func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage) bool {
	currentScan.SSLLabs = !*used
	currentScan.SSLLabsVersion = manager.Version
	if !*used {
		if manager.MaxParallelScans != 0 {
			manager.MaxRetries = *maxRetries
			manager.OutputChannel = channel
			return true
		}
	}
	return false
}

func continueScan(scan hooks.ScanRow) bool {
	if manager.Version != scan.SSLLabsVersion {
		return false
	}
	return true
}

func setUp() {
	if run() != nil {
		// TODO Handle Error
		panic(fmt.Errorf("SSLLabs set up failed"))
	}
}

func init() {
	hooks.ManagerMap[manager.Table] = &manager

	hooks.FlagSetUp[manager.Table] = flagSetUp

	hooks.ConfigureSetUp[manager.Table] = configureSetUp

	hooks.ContinueScan[manager.Table] = continueScan

	hooks.ManagerSetUp[manager.Table] = setUp

	hooks.ManagerHandleScan[manager.Table] = handleScan

	hooks.ManagerHandleResults[manager.Table] = handleResults

}
