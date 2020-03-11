package example

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/structs"

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
	//AnalysisParams []string  `json:"analysis_params"` // "analysis_params": {} // ToDo: cannot unmarshal object into Go struct field TlsObservatoryResult.analysis_params of type []string

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

type CaaWorkerResult struct {
	Host      string `json:"host"`
	Issue     string `json:"issue"`
	HasCaa    bool   `json:"has_caa"`
	Issuewild string `json:"issuewild"`
}

type CrlWorkerResult struct {
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
	Grade       int      `json:"grade"`
	Failures    []string `json:"failures"`
	Lettergrade string   `json:"lettergrade"`
}

type OscpStatusResult struct {
	Status    int       `json:"status"`
	RevokedAt time.Time `json:"revoked_at"`
}

type SslLabsClientSupportResult struct {
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

//	ID                 int    `json:"id"`
//	SerialNumber       string `json:"serialNumber"`
//	Version            int8   `json:"version"`
//	SignatureAlgorithm string `json:"signatureAlgorithm"`
//
//	Issuer struct {
//		ID int      `json:"id"`
//		C  []string `json:"c"`
//		O  []string `json:"o"`
//		CN string   `json:"cn"`
//	} `json:"issuer"`
//
//	Validity struct {
//		NotBefore time.Time `json:"notBefore"`
//		NotAfter  time.Time `json:"notAfter"`
//	} `json:"validity"`
//
//	Subject struct {
//		Cn string `json:"cn"`
//	} `json:"subject"`
//
//	Key struct {
//		Alg      string `json:"alg"`
//		Size     int    `json:"size"`
//		Exponent int    `json:"exponent"`
//	} `json:"key"`
//
//	X509V3Extensions struct {
//		AuthorityKeyId string `json:"authorityKeyId"`
//		SubjectKeyId   string `json:"subjectKeyId"`
//		KeyUsage       struct {
//		}
//	} `json:"x509v3Extensions"`
//}

// TableRow represents the scan results for the crawler table
type TableRow struct {
	ScanStatus int
	//Timestamp      string
	Target string
	Replay int
	HasTls bool
	//CertId int
	//TrustId int
	//Serverside bool
	IsValid bool
	//CompletionPerc int
	//Ack            bool
	//Attempts       int
}

// maxRedirects sets the maximum number of Redirects to be followed
//var maxRedirects int

var maxScans int = 5

var used *bool // Defines if the Observatory TLS scan should be used

//var maxRetries *int

var version = "10"

var manager = hooks.Manager{
	MaxRetries:       3,        //Max Retries
	MaxParallelScans: maxScans, //Max parallel Scans
	Version:          version,
	Table:            "ObservatoryTLS",          //Table name
	ScanType:         hooks.ScanBoth,            // Scan HTTP or HTTPS
	OutputChannel:    nil,                       //output channel
	LogLevel:         hooks.LogNotice,           //loglevel
	Status:           hooks.ScanStatus{},        // initial scanStatus
	FinishError:      0,                         // number of errors while finishing
	ScanID:           0,                         // scanID
	Errors:           []hooks.InternalMessage{}, //errors
	FirstScan:        false,                     //hasn't started first scan
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
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Retrying failed assessment next: %v", scanMsg.Domain.DomainName), manager.LogLevel, hooks.LogTrace)
		} else if len(domains) != 0 {
			scan, retDom = domains[0], domains[1:]
			scanMsg = hooks.InternalMessage{
				Domain:     scan,
				Results:    nil,
				Retries:    0,
				StatusCode: hooks.InternalNew,
			}
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Trying new assessment next: %v", scanMsg.Domain.DomainName), manager.LogLevel, hooks.LogTrace)
		} else {
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("No new assessment started"), manager.LogLevel, hooks.LogTrace)
			return domains
		}
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Started assessment for %v", scanMsg.Domain.DomainName), manager.LogLevel, hooks.LogDebug)
		go assessment(scanMsg, internalChannel)
		manager.Status.AddCurrentScans(1)
		return retDom
	}
	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("no new Assessment started"), manager.LogLevel, hooks.LogTrace)
	return domains
}

func handleResults(result hooks.InternalMessage) {
	res, ok := result.Results.(TableRow)
	manager.Status.AddCurrentScans(-1)

	if !ok {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't assert type of result for  %v", result.Domain.DomainName), manager.LogLevel, hooks.LogError)
		res = TableRow{}
		result.StatusCode = hooks.InternalFatalError
	}

	switch result.StatusCode {
	case hooks.InternalFatalError:
		res.ScanStatus = hooks.StatusError
		manager.Status.AddFatalErrorScans(1)
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Assessment of %v failed ultimately", result.Domain.DomainName), manager.LogLevel, hooks.LogInfo)
	case hooks.InternalSuccess:
		res.ScanStatus = hooks.StatusDone
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Assessment of %v was successful", result.Domain.DomainName), manager.LogLevel, hooks.LogDebug)
		manager.Status.AddFinishedScans(1)
	}
	where := hooks.ScanWhereCond{
		DomainID:    result.Domain.DomainID,
		ScanID:      manager.ScanID,
		TestWithSSL: result.Domain.TestWithSSL}
	err := backend.SaveResults(manager.GetTableName(), structs.New(where), structs.New(res))
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't save results for %v: %v", result.Domain.DomainName, err), manager.LogLevel, hooks.LogError)
		return
	}
	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Results for %v saved", result.Domain.DomainName), manager.LogLevel, hooks.LogDebug)

}

func invokeObservatoryTLSAnalyzation(host string) (TlsObservatoryResult, error) {
	scanApiURL := currentConfig.APILocation + "/scan"

	var scanRequestResponse ScanRequestResponse
	var tlsObservatoryResult TlsObservatoryResult

	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Getting TLS observatory analyzation: %v", host), manager.LogLevel, hooks.LogTrace)

	// Initiate the scan request, the body of the request contains information to hide the scan from the front-page
	response, err := http.Post(scanApiURL, "application/x-www-form-urlencoded",
		strings.NewReader(fmt.Sprintf("rescan=%v&target=%v",
			currentConfig.Rescan,
			host)))
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Received error invoking observatory API for %v : %v", host, err), manager.LogLevel, hooks.LogDebug)
		return TlsObservatoryResult{}, err
	}

	analyzeBody, err := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(analyzeBody, &scanRequestResponse)

	io.Copy(ioutil.Discard, response.Body)
	response.Body.Close()

	hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("TLS Observatory started scan %d for host %v", scanRequestResponse.ScanID, host), manager.LogLevel, hooks.LogDebug)

	// Poll every 5 seconds until scan is done, aborting on abnormal or failed states
	for {
		resultApiURL := currentConfig.APILocation + "/results"
		response, err := http.Get(resultApiURL + fmt.Sprintf("?id=%d", scanRequestResponse.ScanID)) // ToDo: URL formatter
		if err != nil {
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Received error polling TLS Observatory API for %v : %v", host, err), manager.LogLevel, hooks.LogWarning)
			return TlsObservatoryResult{}, err
		} else if response.StatusCode != 200 {
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Got non-200 status code from TLS Observatory API for %v : %v", host, err), manager.LogLevel, hooks.LogWarning)
		}

		tlsObservatoryBody, err := ioutil.ReadAll(response.Body)
		err = json.Unmarshal(tlsObservatoryBody, &tlsObservatoryResult)
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Failed unmarshalling analyzeBody for %v: %v", host, err), manager.LogLevel, hooks.LogWarning)
			return TlsObservatoryResult{}, err
		}

		if tlsObservatoryResult.CompletionPerc < 100 {
			time.Sleep(5 * time.Second)
			continue
		}

		return tlsObservatoryResult, nil
	}
}

func parseResult(result TlsObservatoryResult) TableRow {
	var row TableRow

	//row.Timestamp = result.Timestamp
	row.Target = result.Target
	row.Replay = result.Replay
	row.HasTls = result.HasTls
	//row.CertId = result.CertId
	//row.TrustId = result.TrustId
	//row.Serverside = result.ConnectionInfo.Serverside
	row.IsValid = result.IsValid
	//row.CompletionPerc = result.CompletionPerc
	//row.Ack = result.Ack
	//row.Attempts = result.Attempts

	return row
}

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {
	scanRequestResponse, err := invokeObservatoryTLSAnalyzation(scan.Domain.DomainName)
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't get results from TLS Observatory API for %v: %v", scan.Domain.DomainName, err), manager.LogLevel, hooks.LogError)
		scan.Results = TableRow{}
		scan.StatusCode = hooks.InternalError
		internalChannel <- scan
		return
	}

	row := parseResult(scanRequestResponse)

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
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Failed parsing config to interface: %v", err), manager.LogLevel, hooks.LogError)
	}
	err = json.Unmarshal(jsonString, &currentConfig)
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Failed parsing json to struct: %v", err), manager.LogLevel, hooks.LogError)
	}
	manager.MaxRetries = currentConfig.Retries
	manager.ScanType = currentConfig.ScanType
	maxScans = currentConfig.ParallelScans
	manager.LogLevel = hooks.ParseLogLevel(currentConfig.LogLevel)
}

func continueScan(scan hooks.ScanRow) bool {
	if manager.Version != scan.CrawlerVersion {
		return false
	}
	return true
}

func setUp() {
}

func setUpLogger() {
	manager.Logger = log.New(hooks.LogWriter, "OBS_TLS\t", log.Ldate|log.Ltime)
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

	setUpLogger()
}
