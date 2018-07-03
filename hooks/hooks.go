package hooks

import (
	"database/sql"
	"sync/atomic"
)

// shared Structs
/* ------------------------------------------------------------------------------------------------------------------------*/

// ScanStatus with atomic access
type ScanStatus struct {
	CurrentScans  int32
	TotalScans    int32
	ErrorScans    int32
	FinishedScans int32
}

// ScanStatusMessage with atomic access
type ScanStatusMessage struct {
	Status *ScanStatus
	Sender string
}

// InternalMessage
type InternalMessage struct {
	Domain     DomainsReachable
	Results    interface{}
	Retries    int
	StatusCode int
}

const (
	InternalFatalError = -1
	InternalError      = 0
	InternalSuccess    = 1
	InternalNew        = 2
)

// Diffrent Log-Levels
const (
	LogNone     = -1
	LogEmerg    = 0
	LogAlert    = 1
	LogCritical = 2
	LogError    = 3
	LogWarning  = 4
	LogNotice   = 5
	LogInfo     = 6
	LogDebug    = 7
	LogTrace    = 8
)

// reachable
const (
	ReachableNot  = 0
	ReachableHTTP = 1
	ReachableSSL  = 2
	ReachableBoth = 3
)

// scanTypes
const (
	ScanOnlySSL       = 1
	ScanOnlyHTTP      = 2
	ScanBoth          = 3
	ScanOnePreferSSL  = 4
	ScanOnePreferHTTP = 5
)

const (
	StatusError   = 255
	StatusPending = 0
	StatusDone    = 1
	StatusIgnored = 2
)

// ScanData contains all the fields needed to create entries in the Scan-Tables
type ScanData struct {
	ScanID          int
	DomainID        int
	DomainReachable uint8
}

// DomainsRow represents a row of the domains Table
type DomainsRow struct {
	DomainID   int
	DomainName string
}

// ScanRow represents a row of the ScanTable
type ScanRow struct {
	ScanID                 int
	SSLLabs                bool
	SSLLabsVersion         string
	Observatory            bool
	ObservatoryVersion     string
	SecurityHeaders        bool
	SecurityHeadersVersion string
	Crawler                bool
	CrawlerVersion         string
	Unreachable            int
	Total                  int
	Done                   bool
}

// Manager is a struct which combines values and functions needed by all scans individually
type Manager struct {
	MaxRetries       int
	MaxParallelScans int
	Version          string
	Table            string
	ScanType         int
	OutputChannel    chan ScanStatusMessage
	LogLevel         int
	Status           ScanStatus
	FinishError      int
	ScanID           int
	Errors           []InternalMessage
	FirstScan        bool
}

// DomainsReachable is the base type for receiving the domains which should be scanned
type DomainsReachable struct {
	DomainID        int
	DomainName      string
	DomainReachable int
	TestWithSSL     bool
}

// ScanWhereCond includes all fields needed to specify a particular entry in the Table
type ScanWhereCond struct {
	DomainID    int
	ScanID      int
	TestWithSSL bool
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
	NextThumbprint   sql.NullString
}

func (manager *Manager) GetTableName() string {
	return manager.Table + "V" + manager.Version
}

func (status *ScanStatus) AddCurrentScans(val int32) {
	atomic.AddInt32(&status.CurrentScans, val)
}

func (status *ScanStatus) GetCurrentScans() int32 {
	return atomic.LoadInt32(&status.CurrentScans)
}

func (status *ScanStatus) AddErrorScans(val int32) {
	atomic.AddInt32(&status.ErrorScans, val)
}

func (status *ScanStatus) GetErrorScans() int32 {
	return atomic.LoadInt32(&status.ErrorScans)
}

func (status *ScanStatus) AddFinishedScans(val int32) {
	atomic.AddInt32(&status.FinishedScans, val)
}

func (status *ScanStatus) GetFinishedScans() int32 {
	return atomic.LoadInt32(&status.FinishedScans)
}

func (status *ScanStatus) SetTotalScans(val int32) {
	atomic.StoreInt32(&status.TotalScans, val)
}

func (status *ScanStatus) GetTotalScans() int32 {
	return atomic.LoadInt32(&status.TotalScans)
}

func Truncate(str string, trLen int) string {
	if len(str) > trLen {
		return str[:trLen]
	}
	return str
}

/* ------------------------------------------------------------------------------------------------------------------------*/

// FlagSetUp contains all the API-hooks for adding and parsing flag values
var FlagSetUp map[string]func()

// ConfigureSetUp contains all the API-hooks for configuring the apis based on the commandline flags
var ConfigureSetUp map[string]func(*ScanRow, chan ScanStatusMessage) bool

// ManagerMap is a map of all Managers that can be used
var ManagerMap map[string]*Manager

// ContinueScan contains all the API-hooks to check if the referenced api-version of the scan to be continued is up to date
var ContinueScan map[string]func(ScanRow) bool

// ManagerSetUp contains all the API-hooks to their individual SetUp-Functions
var ManagerSetUp map[string]func()

// ManagerHandleScan contains all the API-hooks to the individual functions needed to start the scans
var ManagerHandleScan map[string]func([]DomainsReachable, chan InternalMessage) []DomainsReachable

// ManagerHandleResults contains all the API-hooks to the individual functions processing the incoming results
var ManagerHandleResults map[string]func(InternalMessage)

func init() {
	FlagSetUp = make(map[string]func())
	ConfigureSetUp = make(map[string]func(*ScanRow, chan ScanStatusMessage) bool)
	ManagerMap = make(map[string]*Manager)
	ContinueScan = make(map[string]func(ScanRow) bool)
	ManagerSetUp = make(map[string]func())
	ManagerHandleScan = make(map[string]func([]DomainsReachable, chan InternalMessage) []DomainsReachable)
	ManagerHandleResults = make(map[string]func(InternalMessage))
}
