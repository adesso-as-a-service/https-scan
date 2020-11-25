package example

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fatih/structs"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"../../backend"
	"../../hooks"
)

type ScanRequestResponse struct {
	ScanID int `json:"scan_id"`
}

type TlsObservatoryResult struct {
	Id             int       `json:"id"`              // "id": 38911638,
	Timestamp      time.Time `json:"timestamp"`       // "timestamp": "2019-11-20T14:43:54.560707Z",
	Target         string    `json:"target"`          // "target": "www.adesso-service.com",
	Replay         int       `json:"replay"`          // "replay": -1,
	HasTls         bool      `json:"has_tls"`         // "has_tls": true,
	CertId         int       `json:"cert_id"`         // "cert_id": 88958679,
	TrustId        int       `json:"trust_id"`        // "trust_id": 148515746,
	IsValid        bool      `json:"is_valid"`        // "is_valid": true,
	CompletionPerc int       `json:"completion_perc"` // "completion_perc": 100,
	Ack            bool      `json:"ack"`             // "ack": true,
	Attempts       int       `json:"attempts"`        // "attempts": 1,

	// The following fields will be filled manually
	AwsCertLintResult             AwsCertLintResult             `json:"-"`
	CAAWorkerResult               CAAWorkerResult               `json:"-"`
	CRLWorkerResult               CRLWorkerResult               `json:"-"`
	MozillaEvaluationWorkerResult MozillaEvaluationWorkerResult `json:"-"`
	MozillaGradingWorkerResult    MozillaGradingWorkerResult    `json:"-"`
	OscpStatusResult              OscpStatusResult              `json:"-"`
	SSLLabsClientSupportResults   []SSLLabsClientSupportResult  `json:"-"`
	SymantecDistrustResult        SymantecDistrustResult        `json:"-"`
	Top1MResult                   Top1MResult                   `json:"-"`

	//AnalysisParams []string  `json:"analysis_params"` // "analysis_params": {} // ToDo: cannot unmarshal object into Go struct field TlsObservatoryResult.analysis_params of type []string
	Analysis []struct {
		Id       int    `json:"id"`
		Analyzer string `json:"analyzer"`

		Success bool `json:"success"`

		Result json.RawMessage `json:"result"`
	} `json:"analysis"`

	ConnectionInfo struct {
		ScanIp     string `json:"scanIP"`     // "scanIP": "85.22.57.97",
		Serverside bool   `json:"serverside"` // "serverside": true,

		Ciphersuite []struct {
			Cipher       string   `json:"cipher"`        // "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
			Code         int      `json:"code"`          // "code": 49200,
			Protocols    []string `json:"protocols"`     // "protocols": ["TLSv1.2"],
			Pubkey       int      `json:"pubkey"`        // "pubkey": 2048,
			Sigalg       string   `json:"sigalg"`        // "sigalg": "sha256WithRSAEncryption",
			TicketHint   string   `json:"ticket_hint"`   // "ticket_hint": "7200",
			OscpStapling bool     `json:"oscp_stapling"` // "ocsp_stapling": false,
			Pfs          string   `json:"pfs"`           // "pfs": "ECDH,P-256,256bits",
			Curves       []string `json:"curves"`        // "curves": ["prime256v1", "secp521r1", "secp384r1", "secp256k1"]
		} `json:"ciphersuite"`
	} `json:"connection_info"`

	AnalyzeResult struct {
		Id       int             `json:"id"`
		Analyzer string          `json:"string"`
		Result   json.RawMessage `json:"result"` // Will be unmarshaled later due to variable structure (https://stackoverflow.com/questions/19691468/json-decode-with-flexible-type)
		Success  bool            `json:"success"`
	} `json:"analsyis"`
}

type AwsCertLintResult struct {
	Bugs          []string `json:"bugs"`
	Errors        []string `json:"errors"`
	Notices       []string `json:"notices"`
	Warnings      []string `json:"warnings"`
	FatalErrors   []string `json:"fatalErrors"`
	Informational []string `json:"informational"`
}

type CAAWorkerResult struct {
	Host      string `json:"host"`
	Issue     string `json:"issue"`
	HasCaa    bool   `json:"has_caa"`
	Issuewild string `json:"issuewild"`
}

type CRLWorkerResult struct {
	Revoked        string    `json:"host"`
	RevocationTime time.Time `json:"RevocationTime"`
}

type MozillaEvaluationWorkerResult struct {
	Level string `json:"level"`

	Failures struct {
		Bad          []string `json:"bad"`
		Old          []string `json:"old"`
		Modern       []string `json:"modern"`
		Intermediate []string `json:"intermediate"`
	} `json:"failures"`
}

type MozillaGradingWorkerResult struct {
	Grade    float32  `json:"grade"`
	Failures []string `json:"failures"`
	//Failures    json.RawMessage `json:"failures"` // can be null or array
	Lettergrade string `json:"lettergrade"`
}

type OscpStatusResult struct {
	Status    int       `json:"status"`
	RevokedAt time.Time `json:"revoked_at"`
}

type SSLLabsClientSupportResult struct {
	Name            string `json:"name"`
	Curve           string `json:"curve"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	CurveCode       int    `json:"curve_code"`
	Ciphersuite     string `json:"ciphersuite"`
	IsSupported     bool   `json:"is_supported"`
	ProtocolCode    int    `json:"protocol_code"`
	CiphersuiteCode int    `json:"ciphersuite_code"`
}

type SymantecDistrustResult struct {
	Reasons      []string `json:"reasons"`
	IsDistrusted bool     `json:"isDistrusted"`
}

type Top1MResult struct {
	Target struct {
		Rank      int    `json:"rank"`
		Domain    string `json:"domain"`
		AlexaRank int    `json:"alexa_rank"`
		CiscoRank int    `json:"cisco_rank"`
	} `json:"target"`

	Certificate struct {
		Rank        int    `json:"rank"`
		Domain      string `json:"domain"`
		AlexaRank   int    `json:"alexa_rank"`
		CiscoRank   int    `json:"cisco_rank"`
		AlexaDomain string `json:"alexa_domain"`
		CiscoDomain string `json:"cisco_domain"`
	} `json:"certificate"`
}

type CertificateInfoResult struct {
	ID                 int    `json:"id"`
	SerialNumber       string `json:"serialNumber"`
	Version            int8   `json:"version"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`

	FirstSeenTimestamp string `json:"firstSeenTimestamp"`
	LastSeenTimestamp  string `json:"lastSeenTimestamp"`

	Raw               string `json:"Raw"`
	CiscoUmbrellaRank int    `json:"ciscoUmbrellaRank"`

	Issuer struct {
		ID int      `json:"id"`
		C  []string `json:"c"`
		O  []string `json:"o"`
		CN string   `json:"cn"`
	} `json:"issuer"`

	Validity struct {
		NotBefore string `json:"notBefore"`
		NotAfter  string `json:"notAfter"`
	} `json:"validity"`

	Subject struct {
		CN string `json:"cn"`
	} `json:"subject"`

	Key struct {
		Alg      string `json:"alg"`
		Size     int    `json:"size"`
		Exponent int    `json:"exponent"`
	} `json:"key"`

	X509V3Extensions struct {
		AuthorityKeyId           string   `json:"authorityKeyId"`
		SubjectKeyId             string   `json:"subjectKeyId"`
		KeyUsage                 []string `json:"keyUsage"`
		ExtendedKeyUsage         []string `json:"extendedKeyUsage"`
		ExtendedKeyUsageOID      []string `json:"extendedKeyUsageOID"`
		SubjectAlternativeName   []string `json:"subjectAlternativeName"`
		CrlDistributionPoint     []string `json:"crlDistributionPoint"`
		PolicyIdentifiers        []string `json:"policyIdentifiers"`
		IsTechnicallyConstrained bool     `json:"isTechnicallyConstrained"`
	} `json:"x509v3Extensions"`

	X509V3BasicConstraints string `json:"x509v3BasicConstraints"`
	CA                     bool   `json:"ca"`

	ValidationInfo struct {
		ValidationInfoItemMap
	} `json:"validationInfo"`

	Hashes struct {
		SHA1                string `json:"sha1"`
		SHA256              string `json:"sha256"`
		SPKI_SHA256         string `json:"spki-sha256"`
		Subject_SPKI_SHA256 string `json:"subject-spki-sha256"`
		Pin_SHA256          string `json:"pin-sha256"`
	} `json:"hashes"`

	MozillaPolicyV2_5 struct {
		IsTechnicallyConstrained bool `json:"IsTechnicallyConstrained"`
	}
}

type ValidationInfoItemMap map[string]ValidationInfoItem

type ValidationInfoItem struct {
	IsValid bool `json:"isValid"`
}

// TableRow represents the scan results for the crawler table
type TableRow struct {
	ScanStatus                       int
	TestWithSSL                      bool
	Target                           string
	ObsScanID                        int
	EndTime                          string
	MozillaEvaluationWorker_Level    string
	MozillaGradingWorker_Grade       float32
	MozillaGradingWorker_Lettergrade string
	Cert_CommonName                  string
	Cert_AlternativeNames            string
	Cert_FirstObserved               string
	Cert_ValidFrom                   string
	Cert_ValidTo                     string
	Cert_Key                         string
	Cert_Issuer                      string
	Cert_SignatureKeyAlgorithm       string
	HasCAARecord                     bool
	ServerSideCipherOrdering         bool
	OCSPStapling                     bool
}

// maxRedirects sets the maximum number of Redirects to be followed
//var maxRedirects int

var maxScans int = 5

var used *bool // Defines if the Observatory TLS scan should be used

//var maxRetries *int

var version = "10"

var manager = hooks.Manager{
	MaxRetries:			3,							//Max Retries
	MaxParallelScans:	maxScans, 					//Max parallel Scans
	Version:			version,
	Table:				"ObservatoryTLS",			//Table name
	ScanType:			hooks.ScanBoth,				// Scan HTTP or HTTPS
	OutputChannel:		nil,						//output channel
	Status:				hooks.ScanStatus{},			// initial scanStatus
	FinishError:		0,							// number of errors while finishing
	ScanID:				0,							// scanID
	Errors:				[]hooks.InternalMessage{},	//errors
	FirstScan:			false,						//hasn't started first scan
	LoggingTag:			"observatorytls",			
}

// Config contains the configurable Values for this scan
type Config struct {
	Retries       int
	ScanType      int
	ParallelScans int
	LogLevel      string
	APILocation   string
	Rescan        bool
}

// defaultConfig
var currentConfig = Config{
	Retries:       3,
	ScanType:      hooks.ScanOnlySSL,
	ParallelScans: 10,
	LogLevel:      "info",
	APILocation:   "https://tls-observatory.services.mozilla.com/api/v1",
	Rescan:        false,
}

func handleScan(domains []hooks.DomainsReachable, internalChannel chan hooks.InternalMessage) []hooks.DomainsReachable {
	for (len(manager.Errors) > 0 || len(domains) > 0) && int(manager.Status.GetCurrentScans()) < manager.MaxParallelScans {
		manager.FirstScan = true
		var scanMsg hooks.InternalMessage
		var retDom = domains
		var scan hooks.DomainsReachable
		// pop first domain
		if manager.CheckDoError() && len(manager.Errors) != 0 {
			scanMsg, manager.Errors = manager.Errors[0], manager.Errors[1:]
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
	res, ok := result.Results.(TableRow)
	manager.Status.AddCurrentScans(-1)

	if !ok {
		manager.Logger.Errorf("Couldn't assert type of result for  %v", result.Domain.DomainName)
		res = TableRow{}
		result.StatusCode = hooks.InternalFatalError
	}

	switch result.StatusCode {
	case hooks.InternalFatalError:
		res.ScanStatus = hooks.StatusError
		manager.Status.AddFatalErrorScans(1)
		manager.Logger.Infof("Assessment of %v failed ultimately", result.Domain.DomainName)
	case hooks.InternalSuccess:
		res.ScanStatus = hooks.StatusDone
		manager.Logger.Debugf("Assessment of %v was successful", result.Domain.DomainName)
		manager.Status.AddFinishedScans(1)
	}
	where := hooks.ScanWhereCond{
		DomainID:    result.Domain.DomainID,
		ScanID:      manager.ScanID,
		TestWithSSL: result.Domain.TestWithSSL}
	err := backend.SaveResults(manager.GetTableName(), structs.New(where), structs.New(res))
	if err != nil {
		manager.Logger.Errorf("Couldn't save results for %v: %v", result.Domain.DomainName, err)
		return
	}
	manager.Logger.Debugf("Results for %v saved", result.Domain.DomainName)
}

func invokeObservatoryTLSAnalyzation(host string) (TlsObservatoryResult, CertificateInfoResult, error) {
	scanApiURL := currentConfig.APILocation + "/scan"

	var scanRequestResponse ScanRequestResponse
	var tlsObservatoryResult TlsObservatoryResult
	var certificateInfoResult CertificateInfoResult

	manager.Logger.Tracef("Getting TLS observatory analyzation: %v", host)

	// Initiate the scan request, the body of the request contains information to hide the scan from the front-page
	response, err := http.Post(scanApiURL, "application/x-www-form-urlencoded",
		strings.NewReader(fmt.Sprintf("rescan=%v&target=%v",
			currentConfig.Rescan,
			host)))
	if err != nil {
		manager.Logger.Debugf("Received error invoking observatory_tls API for %v : %v", host, err)
		return TlsObservatoryResult{}, CertificateInfoResult{}, err
	} else if response.StatusCode != http.StatusOK {
		manager.Logger.Debugf("Received non-OK status code %d from observatory_tls API for %v : %v", response.StatusCode, host, err)
		return TlsObservatoryResult{}, CertificateInfoResult{}, err
	}

	analyzeBody, err := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(analyzeBody, &scanRequestResponse)

	io.Copy(ioutil.Discard, response.Body)
	response.Body.Close()

	manager.Logger.Debugf("TLS Observatory started scan %d for host %v", scanRequestResponse.ScanID, host)

	// Poll every 5 seconds until scan is done, aborting on abnormal or failed states
	for {
		resultApiURL := currentConfig.APILocation + "/results"
		response, err := http.Get(resultApiURL + fmt.Sprintf("?id=%d", scanRequestResponse.ScanID)) // ToDo: URL formatter
		if err != nil {
			manager.Logger.Warningf("Received error polling TLS Observatory API for %v : %v", host, err)
			return TlsObservatoryResult{}, CertificateInfoResult{}, err
		} else if response.StatusCode != http.StatusOK {
			manager.Logger.Warningf("Got non-OK status code from TLS Observatory API for %v : %v", host, err)
			return TlsObservatoryResult{}, CertificateInfoResult{}, err

		}

		tlsObservatoryBody, err := ioutil.ReadAll(response.Body)
		err = json.Unmarshal(tlsObservatoryBody, &tlsObservatoryResult)
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			manager.Logger.Warningf("Failed unmarshalling analyzeBody for %v: %v", host, err)
			return TlsObservatoryResult{}, CertificateInfoResult{}, err
		}

		if tlsObservatoryResult.CompletionPerc < 100 {
			time.Sleep(5 * time.Second)
			continue
		}

		break
	}

	// unmarshal indiviual results
	for _, element := range tlsObservatoryResult.Analysis {
		switch element.Analyzer {
		case "awsCertlint":
			var awsCertLintResult AwsCertLintResult
			err = json.Unmarshal(element.Result, &awsCertLintResult)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.AwsCertLintResult = awsCertLintResult
		case "caaWorker":
			var caaWorkerResult CAAWorkerResult
			err = json.Unmarshal(element.Result, &caaWorkerResult)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.CAAWorkerResult = caaWorkerResult
		case "crlWorker":
			var crlWorkerResult CRLWorkerResult
			err = json.Unmarshal(element.Result, &crlWorkerResult)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.CRLWorkerResult = crlWorkerResult
		case "mozillaEvaluationWorker":
			var mozillaEvaluationWorkerResult MozillaEvaluationWorkerResult
			err = json.Unmarshal(element.Result, &mozillaEvaluationWorkerResult)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.MozillaEvaluationWorkerResult = mozillaEvaluationWorkerResult
		case "mozillaGradingWorker":
			var mozillaGradingWorkerResult MozillaGradingWorkerResult
			err = json.Unmarshal(element.Result, &mozillaGradingWorkerResult)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.MozillaGradingWorkerResult = mozillaGradingWorkerResult
		case "ocspStatus":
			var oscpStatusResult OscpStatusResult
			err = json.Unmarshal(element.Result, &oscpStatusResult)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.OscpStatusResult = oscpStatusResult
		case "sslLabsClientSupport":
			var sslLabsClientSupportResults []SSLLabsClientSupportResult
			err = json.Unmarshal(element.Result, &sslLabsClientSupportResults)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.SSLLabsClientSupportResults = sslLabsClientSupportResults
		case "symantecDistrust":
			var symantecDistrustResult SymantecDistrustResult
			err = json.Unmarshal(element.Result, &symantecDistrustResult)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.SymantecDistrustResult = symantecDistrustResult
		case "top1m":
			var top1MResult Top1MResult
			err = json.Unmarshal(element.Result, &top1MResult)
			if err != nil {
				manager.Logger.Warningf("Failed unmarshalling %v for %v: %v", element.Analyzer, host, err)
				return TlsObservatoryResult{}, CertificateInfoResult{}, err
			}
			tlsObservatoryResult.Top1MResult = top1MResult
		default:
			manager.Logger.Warningf("Unknown Analyzer scan result %v", element.Analyzer)
		}
	}

	for {
		certificateInfoApiURL := currentConfig.APILocation + "/certificate"

		response, err := http.Get(certificateInfoApiURL + fmt.Sprintf("?id=%d", tlsObservatoryResult.CertId)) // ToDo: URL formatter

		if err != nil {
			manager.Logger.Warningf("Received error polling TLS Observatory certificate API for %v : %v", host, err)
			return TlsObservatoryResult{}, CertificateInfoResult{}, err
		} else if response.StatusCode != http.StatusOK {
			manager.Logger.Warningf("Got non-OK status code from TLS Observatory certificate API for %v : %v", host, err)
			return TlsObservatoryResult{}, CertificateInfoResult{}, err
		}

		certificateInfoBody, err := ioutil.ReadAll(response.Body)
		err = json.Unmarshal(certificateInfoBody, &certificateInfoResult)
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			manager.Logger.Warningf("Failed unmarshalling certificateInfoBody for %v: %v", host, err)
			return TlsObservatoryResult{}, CertificateInfoResult{}, err
		}

		return tlsObservatoryResult, certificateInfoResult, nil
	}
}

func parseResult(tlsObservatoryResult TlsObservatoryResult, certificateInfoResult CertificateInfoResult) TableRow {
	var row TableRow

	var err error
	alternativeNamesBytes, err := json.Marshal(certificateInfoResult.X509V3Extensions.SubjectAlternativeName)
	if err != nil {
		manager.Logger.Errorf("TLS Observatory - failed to marshal Alternative Names for %v: %v", tlsObservatoryResult.Target, err)
	}

	//firstObserved, err := time.Parse("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'", certificateInfoResult.FirstSeenTimestamp)
	firstObserved, err := time.Parse(time.RFC3339, certificateInfoResult.FirstSeenTimestamp)
	if err != nil {
		manager.Logger.Errorf("TLS Observatory - failed to parse FirstSeen timestamp for %v: %v", tlsObservatoryResult.Target, err)
	}

	row.TestWithSSL = true // ToDo: Is this supposed to be set here?

	row.Target = tlsObservatoryResult.Target
	row.ObsScanID = tlsObservatoryResult.Id
	row.EndTime = certificateInfoResult.Validity.NotAfter // ToDo: duplicate value?
	row.MozillaEvaluationWorker_Level = tlsObservatoryResult.MozillaEvaluationWorkerResult.Level
	row.MozillaGradingWorker_Grade = tlsObservatoryResult.MozillaGradingWorkerResult.Grade
	row.MozillaGradingWorker_Lettergrade = tlsObservatoryResult.MozillaGradingWorkerResult.Lettergrade
	row.Cert_CommonName = certificateInfoResult.Subject.CN
	row.Cert_AlternativeNames = string(alternativeNamesBytes)
	row.Cert_FirstObserved = firstObserved.Format("2006-01-02 15:04:05")
	row.Cert_ValidFrom = certificateInfoResult.Validity.NotBefore
	row.Cert_ValidTo = certificateInfoResult.Validity.NotAfter
	row.Cert_Key = fmt.Sprintf("%s %d bits", certificateInfoResult.Key.Alg, certificateInfoResult.Key.Size)
	row.Cert_Issuer = certificateInfoResult.Issuer.CN
	row.Cert_SignatureKeyAlgorithm = certificateInfoResult.SignatureAlgorithm
	row.HasCAARecord = tlsObservatoryResult.CAAWorkerResult.HasCaa
	row.ServerSideCipherOrdering = tlsObservatoryResult.ConnectionInfo.Serverside

	row.OCSPStapling = false
	for _, cipherSuite := range tlsObservatoryResult.ConnectionInfo.Ciphersuite {
		if cipherSuite.OscpStapling {
			row.OCSPStapling = true
			break
		}
	}

	return row
}

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {
	scanRequestResponse, certificateInfoResult, err := invokeObservatoryTLSAnalyzation(scan.Domain.DomainName)
	if err != nil {
		manager.Logger.Errorf("Couldn't get results from TLS Observatory API for %v: %v", scan.Domain.DomainName, err)
		scan.Results = TableRow{}
		scan.StatusCode = hooks.InternalError
		internalChannel <- scan
		return
	}

	row := parseResult(scanRequestResponse, certificateInfoResult)

	//return results
	scan.Results = row
	scan.StatusCode = hooks.InternalSuccess
	internalChannel <- scan
}

func flagSetUp() {
	used = flag.Bool("no-obs-tls", false, "Don't use the Mozilla TLS-Observatory-Scan")
}

func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage, config interface{}) bool {
	currentScan.Crawler = !*used
	currentScan.CrawlerVersion = manager.Version
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
}

func continueScan(scan hooks.ScanRow) bool {
	if manager.Version != scan.CrawlerVersion {
		return false
	}
	return true
}

func setUp() {
	var logger = hooks.Logger
	manager.Logger = logger.WithField("hook", manager.LoggingTag)
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
