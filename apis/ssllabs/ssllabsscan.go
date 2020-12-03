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
	"github.com/sirupsen/logrus"
	"io/ioutil"
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
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
	LoggingTag:       "ssllabs",
}

// CrawlerConfig
type Config struct {
	Retries              int
	ScanType             int
	ParallelScans        int
	APILocation          string
	IgnoreMismatch       bool
	StartNew             bool
	FromCache            bool
	MaxAge               int
	NewAssessmentCoolOff int64
}

// defaultConfig
var currentConfig = Config{
	Retries:              3,
	ScanType:             hooks.ScanOnlySSL,
	ParallelScans:        10,
	APILocation:          "https://api.ssllabs.com/api/v3",
	IgnoreMismatch:       true,
	StartNew:             false,
	FromCache:            true,
	MaxAge:               24,
	NewAssessmentCoolOff: 1100,
}

var USER_AGENT = "ssllabs-scan v1.5.0 (dev $Id$)"

// How many assessments does the server think we have in progress?
var currentAssessments = -1

// The maximum number of assessments we can have in progress at any one time.
var maxAssessments = -1

var requestCounter uint64

var APILocation = "https://api.ssllabs.com/api/v3"

var newAssessmentCoolOff int64 = currentConfig.NewAssessmentCoolOff

var ignoreMismatch = true

var startNew = true

var fromCache = false

var maxAge = 0

var insecure = false

var httpClient *http.Client

var lastTime time.Time

var certificatesTable = "CertificatesV10"
var certificateChainsTable = "CertificateChainsV10"

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
	IP                             string
	StartTime                      string
	TestTime                       string
	Grade                          string
	GradeTrustIgnored              string
	FutureGrade                    string
	HasWarnings                    bool
	IsExceptional                  bool
	NumberWeakProtocols            int
	WeakProtocols                  string
	NumberProtocols                int
	Protocols                      string
	NumberWeakSuites               int
	WeakSuites                     string
	NumberSuites                   int
	Suites                         string
	ForwardSecrecy                 uint8
	RenegSupport                   uint8
	SupportsRC4                    bool
	VulnBeast                      bool
	VulnHeartbleed                 bool
	VulnOpenSslCcs                 int16
	VulnOpenSSLLuckyMinus20        int16
	VulnTicketbleed                uint8
	VulnBleichenbacher             int16
	VulnPoodle                     uint8
	VulnFreak                      bool
	VulnLogjam                     bool
	VulnDrown                      bool
	DhUsesKnownPrimes              uint8
	DhYsReuse                      bool
	EcdhParameterReuse             bool
	CertificateChainIssues         int16
	CertificateChainLength         uint8
	EndEntityCertificateThumbprint sql.NullString
	ScanStatus                     int
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
	Sha256Hash             string
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
	Id         string
	CertIds    []string
	Trustpaths []LabsTrustPath
	Issues     int
	NoSni      bool
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

		manager.Logger.Tracef("Request #%v: %v", reqId, url)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Add("User-Agent", USER_AGENT)

		resp, err := httpClient.Do(req)
		if err == nil {
			manager.Logger.WithFields(logrus.Fields{
				"protocol": resp.Proto,
				"status":   resp.Status,
			}).Tracef("Response #%v", reqId)

			for key, values := range resp.Header {
				for _, value := range values {
					manager.Logger.WithFields(logrus.Fields{
						"key":   key,
						"value": value,
					}).Tracef("invokeGetRepeatedly Header")
				}
			}

			for key, values := range resp.Header {
				if strings.ToLower(key) == "x-message" {
					for _, value := range values {
						manager.Logger.WithFields(logrus.Fields{"message": value}).Infof("Received SSL Labs Server message")
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
						manager.Logger.Infof("Server set current assessments to %v", headerValue)
					}
				} else {
					manager.Logger.Warnf("Ignoring invalid X-Current-Assessments value (%v): %v", headerValue, err)
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
							manager.Logger.Panicf("Server doesn't allow further API requests")
						}

						manager.Logger.Debugf("Server set maximum assessments to %v", headerValue)
					}
				} else {
					manager.Logger.Warnf("Ignoring invalid X-Max-Assessments value (%v): %v", headerValue, err)
				}
			}

			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, nil, err
			}

			manager.Logger.WithFields(logrus.Fields{
				"body": string(body),
			}).Tracef("Response #%v", reqId)

			return resp, body, nil
		}

		if strings.Contains(err.Error(), "EOF") {
			// Server closed a persistent connection on us, which
			// Go doesn't seem to be handling well. So we'll try one
			// more time.
			if retryCount > 5 {
				manager.Logger.Error("Too many HTTP requests (5) failed with EOF (ref#2)")

			}

			manager.Logger.Debugf("HTTP request failed with EOF (ref#2)")

		} else {
			manager.Logger.Errorf("HTTP request failed: %v (ref#2)", err.Error())
		}

		retryCount++

	}
}

func invokeApi(command string) (*http.Response, []byte, error) {
	var url = APILocation + "/" + command
	sleepCounter := 0

	for {
		resp, body, err := invokeGetRepeatedly(url)
		if err != nil {
			return nil, nil, err
		}

		// Status codes 429, 503, and 529 essentially mean try later. Thus,
		// if we encounter them, we sleep for a while and try again.
		switch resp.StatusCode {
		case http.StatusOK:
			return resp, body, nil
		case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusForbidden, 529:
			// In case of the overloaded server, randomize the sleep time so
			// that some clients reconnect earlier and some later.

			logInfoFields := logrus.Fields{
				"response_body": string(body),
				"response_code": resp.StatusCode,
				"command":       command,
			}

			if sleepCounter >= 5 {
				manager.Logger.WithFields(logInfoFields).Warnf("Abandoning scan after %d tries to call SSLLabs API", sleepCounter)

				return resp, body, errors.New(fmt.Sprintf("Assessment failed for command '%v' with response code %v (slept for too long)", command, resp.StatusCode))
			}

			manager.Logger.WithFields(logInfoFields).Trace("SSLLabs API request was unsuccessful. Sleeping until retry")

			sleepCounter += 1
			sleepTime := 60 + rand.Int31n(60)

			manager.Logger.Infof("Sleeping for %v Seconds after response code %v for command '%v'", sleepTime, resp.StatusCode, command)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		default:
			return resp, body, errors.New(fmt.Sprintf("Unexpected response status code %v for command '%v'", resp.StatusCode, command))
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
		manager.Logger.Errorf("JSON unmarshal error: %v", err)

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
			manager.Logger.Errorf("JSON unmarshal error: %v", err)
			return nil, err
		}

		return nil, apiError
	}
	// We should have a proper response.

	var analyzeResponse LabsReport
	err = json.Unmarshal(body, &analyzeResponse)
	if err != nil {
		manager.Logger.Errorf("JSON unmarshal error: %v", err)
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
			manager.Logger.Errorf("Assessment failed for %v: %v", scan.Domain.DomainName, err)
			scan.StatusCode = hooks.InternalError
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
				manager.Logger.Errorf("Assessment failed for %v: received time is older than starttime", scan.Domain.DomainName)
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
	if report.Status == "READY" {
		scan.StatusCode = hooks.StatusDone
	} else {
		manager.Logger.Errorf("Assessment failed for %v: Received ERROR-Response from ssllabs-API: %v", scan.Domain.DomainName, report.StatusMessage)
		scan.StatusCode = hooks.StatusError
	}

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

	manager.Logger.Infof("SSL Labs v%v (criteria version %v)", labsInfo.EngineVersion, labsInfo.CriteriaVersion)

	for _, message := range labsInfo.Messages {
		manager.Logger.Infof("Server message: %v", message)
	}

	maxAssessments = labsInfo.MaxAssessments

	if maxAssessments <= 0 {
		manager.Logger.Warnf("You're not allowed to request new assessments")
	}

	if labsInfo.NewAssessmentCoolOff >= 1000 {
		newAssessmentCoolOff = 100 + labsInfo.NewAssessmentCoolOff
	} else {
		manager.Logger.Warnf("Info.NewAssessmentCoolOff too small: %v", labsInfo.NewAssessmentCoolOff)

	}
	lastTime = time.Now()
	return nil
}

func handleScan(domains []hooks.DomainsReachable, internalChannel chan hooks.InternalMessage) []hooks.DomainsReachable {
	for (len(manager.Errors) > 0 || len(domains) > 0) && currentAssessments < maxAssessments && time.Since(lastTime) > time.Duration(newAssessmentCoolOff)*time.Millisecond {
		manager.FirstScan = true
		lastTime = time.Now()
		var scanMsg hooks.InternalMessage
		var retDom = domains
		var scan hooks.DomainsReachable
		// pop fist domain
		if manager.CheckDoError() && len(manager.Errors) != 0 {
			scanMsg, manager.Errors = manager.Errors[0], manager.Errors[1:]
			retDom = domains
			manager.Logger.Tracef("Retrying failed assessment next: %v", scanMsg.Domain.DomainName)
		} else if len(domains) != 0 {
			scan, retDom = domains[0], domains[1:]
			scanMsg = hooks.InternalMessage{
				Domain:     scan,
				Results:    nil,
				Retries:    0,
				StatusCode: hooks.InternalNew,
			}
			manager.Logger.Tracef("Trying new assessment next: %v", scanMsg.Domain.DomainName)
		} else {
			manager.Logger.Tracef("No new assessment started")
			return domains
		}
		manager.Logger.Debugf("Started assessment for %v", scanMsg.Domain.DomainName)
		go assessment(scanMsg, internalChannel)
		manager.Status.AddCurrentScans(1)
		return retDom
	}
	manager.Logger.Tracef("no new Assessment started")
	return domains
}

func handleResults(result hooks.InternalMessage) {
	manager.Status.AddCurrentScans(-1)
	res, ok := result.Results.(*LabsReport)
	if !ok {
		manager.Logger.Errorf("Couldn't assert type of result for  %v", result.Domain.DomainName)
		res = &LabsReport{}
		result.StatusCode = hooks.InternalFatalError
	}

	labsRes := makeSSLLabsRow(res)

	switch result.StatusCode {
	case hooks.InternalFatalError:
		labsRes.ScanStatus = hooks.StatusError
		manager.Status.AddFatalErrorScans(1)
		manager.Logger.Infof("Assessment of %v failed ultimately", result.Domain.DomainName)
	case hooks.InternalSuccess:
		labsRes.ScanStatus = hooks.StatusDone
		manager.Logger.Debugf("Assessment of %v was successful", result.Domain.DomainName)
		manager.Status.AddFinishedScans(1)
	}

	certRows := makeCertificateRows(res)
	err := backend.SaveCertificates(certRows, certificatesTable)
	if err != nil {
		manager.Logger.Errorf("Couldn't save certificates for %v: %v", result.Domain.DomainName, err)
		return
	}

	certChainRows := makeCertificateChainRows(res)
	err = backend.SaveCertificateChains(certChainRows, certificateChainsTable)
	if err != nil {
		manager.Logger.Errorf("Couldn't save certificate chains for %v: %v", result.Domain.DomainName, err)
		return
	}

	where := hooks.ScanWhereCond{
		DomainID:    result.Domain.DomainID,
		ScanID:      manager.ScanID,
		TestWithSSL: result.Domain.TestWithSSL}
	err = backend.SaveResults(manager.GetTableName(), structs.New(where), structs.New(labsRes))
	if err != nil {
		manager.Logger.Errorf("Couldn't save results for %v: %v", result.Domain.DomainName, err)
		return
	}
	manager.Logger.Debugf("Results for %v saved", result.Domain.DomainName)
}

func makeCertificateRows(report *LabsReport) []*hooks.CertificateRow {
	var res = []*hooks.CertificateRow{}
	if len(report.Endpoints) == 0 {
		manager.Logger.Errorf("Couldn't read certificates for %v: no endpoints", report.Host)
		return res
	}
	for _, cert := range report.Certs {
		row := &hooks.CertificateRow{}
		row.ThumbprintSHA256 = hooks.Truncate(cert.Sha256Hash, 64)
		row.ThumbprintSHA1 = hooks.Truncate(cert.Sha1Hash, 40)
		row.SerialNumber = hooks.Truncate(cert.SerialNumber, 100)
		row.Subject = hooks.Truncate(cert.Subject, 300)
		row.IssuerSubject = hooks.Truncate(cert.IssuerSubject, 300)
		row.SigAlg = hooks.Truncate(cert.SigAlg, 30)
		row.RevocationStatus = uint8(cert.RevocationStatus)
		row.Issues = int16(cert.Issues)
		row.KeyStrength = int16(cert.KeyStrength)
		row.DebianInsecure = cert.KeyKnownDebianInsecure
		row.ValidTo = time.Unix(cert.NotAfter/1000, 0).Format("2006-01-02 15:04:05")
		row.ValidFrom = time.Unix(cert.NotBefore/1000, 0).Format("2006-01-02 15:04:05")
		row.CommonNames = strings.Join(cert.CommonNames, ", ")
		row.AltNames = strings.Join(cert.AltNames, ", ")

		row.CreatedAt = time.Now().Format("2006-01-02 15:04:05")
		row.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")

		res = append([]*hooks.CertificateRow{row}, res...)
	}
	return res
}

func makeCertificateChainRows(report *LabsReport) []*hooks.CertificateChainRow {
	var res = []*hooks.CertificateChainRow{}
	if len(report.Endpoints) == 0 {
		manager.Logger.Errorf("Couldn't read certificate chains for %v: no endpoints", report.Host)
		return res
	}

	for _, endpoint := range report.Endpoints {
		for _, certChain := range endpoint.Details.CertChains {
			for _, trustPath := range certChain.Trustpaths {
				// We choose to use chains that are trusted by Mozilla (also available: Apple, Android, Windows, Java)
				isMozillaTrusted := false
				for _, trust := range trustPath.Trust {
					if trust.IsTrusted && trust.RootStore == "Mozilla" {
						isMozillaTrusted = true
						break
					}
				}

				if !isMozillaTrusted {
					continue
				}

				for i, certId := range trustPath.CertIds {
					// The last certificate is a root certificate without a next certificate and does not need a table entry
					if i == (len(trustPath.CertIds) - 1) {
						continue
					}

					row := &hooks.CertificateChainRow{}
					row.ThumbprintSHA256 = hooks.Truncate(certId, 64)

					// If there is a next certificate in the API response, it is also the next certificate in the chain
					row.NextThumbprintSHA256 = hooks.Truncate(trustPath.CertIds[i+1], 64)

					row.CreatedAt = time.Now().Format("2006-01-02 15:04:05")
					row.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")

					res = append([]*hooks.CertificateChainRow{row}, res...)
				}
			}
		}
	}

	return res
}

func makeSSLLabsRow(report *LabsReport) *TableRow {
	var helpInt int
	var helpStr string
	if len(report.Endpoints) == 0 {
		manager.Logger.Errorf("Couldn't read report for %v: no endpoints", report.Host)
		return &TableRow{}
	}
	endpoint := report.Endpoints[0]
	details := endpoint.Details
	row := &TableRow{}
	row.IP = hooks.Truncate(endpoint.IpAddress, 15)
	row.StartTime = time.Unix(report.StartTime/1000, 0).Format("2006-01-02 15:04:05")
	row.TestTime = time.Unix(report.TestTime/1000, 0).Format("2006-01-02 15:04:05")
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
		row.EndEntityCertificateThumbprint = sql.NullString{
			String: hooks.Truncate(report.Certs[0].Sha1Hash, 40),
			Valid:  true,
		}
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
}

func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage, config interface{}) bool {
	currentScan.SSLLabs = !*used
	currentScan.SSLLabsVersion = manager.Version
	if !*used {
		if manager.MaxParallelScans != 0 {
			parseConfig(config)
			manager.OutputChannel = channel
			return true
		}
	}
	return false
}

// reads Config from interfaceFormat to Config and saves Results
func parseConfig(config interface{}) {
	jsonString, err := json.Marshal(config)
	if err != nil {
		manager.Logger.Errorf("Failed parsing config to interface: %v", err)
	}
	err = json.Unmarshal(jsonString, &currentConfig)
	if err != nil {
		manager.Logger.Errorf("Failed parsing json to struct: %v", err)
	}
	manager.MaxRetries = currentConfig.Retries
	manager.ScanType = currentConfig.ScanType
	maxScans = currentConfig.ParallelScans
	APILocation = currentConfig.APILocation
	fromCache = currentConfig.FromCache
	ignoreMismatch = currentConfig.IgnoreMismatch
	maxAge = currentConfig.MaxAge
	startNew = currentConfig.StartNew
	newAssessmentCoolOff = currentConfig.NewAssessmentCoolOff
}

func continueScan(scan hooks.ScanRow) bool {
	return manager.Version == scan.SSLLabsVersion
}

func setUp() {
	var logger = hooks.Logger
	manager.Logger = logger.WithField("hook", manager.LoggingTag)

	if err := run(); err != nil {
		manager.Logger.WithFields(logrus.Fields{"error": err}).Panicf("Failed Setting Up")
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

	hooks.ManagerParseConfig[manager.Table] = parseConfig
}
