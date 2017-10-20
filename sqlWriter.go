package main

import _ "github.com/denisenkom/go-mssqldb"

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var globalSQLRetries = -1

// How many assessment do we have in progress?
var activeSqlAssessments = 0

// The maximum number of assessments we can have in progress at any one time.
var maxSqlAssessments = 10

type SqlConfiguration struct {
	SqlServer     string
	SqlUserId     string
	SqlPassword   string
	SqlDatabase   string
	SqlEncryption string
	SqlTable      string
}

func msUnixToTime(ms int64) time.Time {
	return time.Unix(0, ms*int64(time.Millisecond))
}

func readSqlConfig(file string) SqlConfiguration {
	configFile, err := os.Open("sql_config.json")
	if err != nil {
		log.Fatalf("[ERROR] Opening specified sql_config failed: %v", err)
	}
	decoder := json.NewDecoder(configFile)
	configuration := SqlConfiguration{}
	decoderErr := decoder.Decode(&configuration)
	if decoderErr != nil {
		log.Fatalf("[ERROR] Decoding sql_config failed: %v", err)
	}
	configFile.Close()
	return configuration
}

func writeToDb(report *LabsReport) error {
	// Insert Infos into Database
	currentReport := report
	// Go through the endpoints and add information from within to variables that can be used
	// When building the SQL-Query
	for k := range currentReport.Endpoints {
		currentEndpoint := currentReport.Endpoints[k]

		prefixSupport := false
		if currentEndpoint.Details.PrefixDelegation == true && currentEndpoint.Details.NonPrefixDelegation == true {
			prefixSupport = true
		}

		var protocolString string
		for m := range currentEndpoint.Details.Protocols {
			currentProtocol := currentEndpoint.Details.Protocols[m]
			protocolString += currentProtocol.Name + currentProtocol.Version
		}

		supportsSSL20 := false
		supportsSSL30 := false
		supportsTLS10 := false
		supportsTLS11 := false
		supportsTLS12 := false
		if strings.Contains(protocolString, "SSL2.0") {
			supportsSSL20 = true
		}
		if strings.Contains(protocolString, "SSL3.0") {
			supportsSSL30 = true
		}
		if strings.Contains(protocolString, "TLS1.0") {
			supportsTLS10 = true
		}
		if strings.Contains(protocolString, "TLS1.1") {
			supportsTLS11 = true
		}
		if strings.Contains(protocolString, "TLS1.2") {
			supportsTLS12 = true
		}

		var suites string
		for m := range currentEndpoint.Details.Suites.List {
			currentSuite := currentEndpoint.Details.Suites.List[m]
			suites += currentSuite.Name + fmt.Sprintf(" (cStr: %v ", currentSuite.CipherStrength)
			if currentSuite.EcdhStrength != 0 {
				suites += fmt.Sprintf("ecdhStr: %v ", currentSuite.EcdhStrength)
			}
			if currentSuite.EcdhBits != 0 {
				suites += fmt.Sprintf("ecdhBits: %v", currentSuite.EcdhBits)
			}
			suites += ")"
		}

		var sims string
		for m := range currentEndpoint.Details.Sims.Results {
			currentSim := currentEndpoint.Details.Sims.Results[m]
			sims += fmt.Sprintf("%v (%v %v %v %v);", currentSim.Client.Id, currentSim.ErrorCode, currentSim.Attempts, currentSim.ProtocolId, currentSim.SuiteId)
		}

		var hstsPreloads string
		for m := range currentEndpoint.Details.HstsPreloads {
			currentPreload := currentEndpoint.Details.HstsPreloads[m]
			hstsPreloads += fmt.Sprintf("%v:%v;", currentPreload.Source, currentPreload.Status)
		}

		// Encase in string() when used
		hpkpPolicy, err := json.Marshal(currentEndpoint.Details.HpkpPolicy)
		hpkpRoPolicy, err := json.Marshal(currentEndpoint.Details.HpkpRoPolicy)

		var hstsPolicyDirectives string
		hstsPolicyDirectives += fmt.Sprintf("max-age : \"%v\" ;", currentEndpoint.Details.HstsPolicy.Directives.MaxAge)
		hstsPolicyDirectives += fmt.Sprintf("includesubdomains : \"%v\" ;", currentEndpoint.Details.HstsPolicy.Directives.Includesubdomains)
		hstsPolicyDirectives += fmt.Sprintf("preload : \"%v\" ;", currentEndpoint.Details.HstsPolicy.Directives.Preload)

		var chainIssuers string
		var subject string
		var issuer string
		var signatureAlg string
		var keyAlg string
		var keySize int
		var chainSize int
		var chainData string
		var chainSha1Hashes string
		var chainPinSha256 string
		for m := range currentEndpoint.Details.Chain.Certs {
			currentChainCert := currentEndpoint.Details.Chain.Certs[m]
			chainIssuers += currentChainCert.IssuerLabel + "|"
			subject += currentChainCert.Subject + "|"
			issuer += currentChainCert.IssuerLabel + "|"
			signatureAlg += currentChainCert.SigAlg + "|"
			keyAlg += currentChainCert.KeyAlg + "|"
			keySize = currentChainCert.KeySize
			chainSize += len(currentChainCert.Raw)
			chainData += currentChainCert.Raw + "\n"
			chainSha1Hashes += currentChainCert.Sha1Hash + "|"
			chainPinSha256 += currentChainCert.PinSha256 + "|"
		}

		var observatoryPassFail string
		var observatoryDescriptions string
		if globalObservatory {
			observatoryPassFail = strconv.Itoa(currentReport.ObservatoryScan.TestsPassed) + "/" + strconv.Itoa(currentReport.ObservatoryScan.TestsFailed)
			observatoryDescriptions = currentReport.ObservatoryResults.ToIssueString()
		}

		sqlConfiguration := readSqlConfig("sql_config.json")
		var table string = sqlConfiguration.SqlTable
		query := fmt.Sprintf(`Insert into %v (DomainName, DomainDepth, IpAddress, Port, CheckTime, Grade, HasWarnings,
			IsExceptional, RequestDuration, CertSubject, CommonName, AltNames, AltNameCount, PrefixSupport, Issuer,
			NotAfter, NotBefore, SignatureAlg, KeyAlg, KeySize, ValidationType, IsSgc, RevocationInfo, ChainLength,
			ChainIssuers, ChainData, IsTrusted, SupportsSSL20, SupportsSSL30, SupportsTLS10, SupportsTLS11,
			SupportsTLS12, Suites, SuiteCount, SuitesInOrder, ServerSignature, DebianFlawed, SessionResumption, 
			RenegSupport, ChainIssues, EngineVersion, CriteriaVersion, CrlUris, OcspUris, VulnBEAST, Compression, 
			NpnSupport, NpnProtocols, SessionTickets, OcspStapling, SniRequired, HttpStatusCode, HttpForwarding, 
			KeyStrength, Sims, ForwardSecrecy, Heartbeat, Heartbleed, Poodle, PoodleTls, Logjam, Freak, OpenSslCcs, 
			DhYsReuse, DhPrimeCount, DhPrimeList, SupportsRc4, Rc4WithModern, DhUsesKnownPrimes, HstsPolicyMaxAge, 
			HstsPolicyHeader, HstsPolicyStatus, HstsPolicyIncludeSubdomains, HstsPolicyPreload, HstsPolicyDirectives, 
			HpkpPolicy, HpkpRoPolicy, HasSct, chainPinSha256, chainSha1Hashes, Rc4Only, ChaCha20Preference, 
			DrownVulnerable, MustStaple, OpenSSLLuckyMinus20, SecurityHeadersGrade, SecurityHeadersXFrameOptions, 
			SecurityHeadersStrictTransportSecurity, SecurityHeadersXContentTypeOptions, SecurityHeadersXXSSProtection, 
			ObservatoryRating, ObservatoryPassFail, ObservatoryIssues)
			values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, table)
		db, err := sql.Open("mssql", fmt.Sprintf("server=%v;user id=%v;password=%v;database=%v;encrypt=%v",
			sqlConfiguration.SqlServer, sqlConfiguration.SqlUserId, sqlConfiguration.SqlPassword, sqlConfiguration.SqlDatabase, sqlConfiguration.SqlEncryption))
		if err != nil {
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Connecting to SQL-Server: %v", err)
			}
			db.Close()
			return err
		}
		if err := db.Ping(); err != nil {
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Can't ping SQL-Server: %v", err)
			}
			db.Close()
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Can't begin SQL-Transaction: %v", err)
			}
			db.Close()
			return err
		}
		result, err := db.Exec(query, currentReport.Host, len(currentReport.Endpoints), currentEndpoint.IpAddress, currentReport.Port, msUnixToTime(currentReport.TestTime), currentEndpoint.Grade, currentEndpoint.HasWarnings, currentEndpoint.IsExceptional, currentEndpoint.Duration, subject, strings.Join(currentEndpoint.Details.Cert.CommonNames, ";"), strings.Join(currentEndpoint.Details.Cert.AltNames, ";"), len(currentEndpoint.Details.Cert.AltNames), prefixSupport, issuer, msUnixToTime(currentEndpoint.Details.Cert.NotAfter), msUnixToTime(currentEndpoint.Details.Cert.NotBefore), signatureAlg, keyAlg, keySize, currentEndpoint.Details.Cert.ValidationType, currentEndpoint.Details.Cert.Sgc, currentEndpoint.Details.Cert.RevocationInfo, len(currentEndpoint.Details.Chain.Certs), chainIssuers, chainData, currentEndpoint.Details.Cert.Issues, supportsSSL20, supportsSSL30, supportsTLS10, supportsTLS11, supportsTLS12, suites, len(currentEndpoint.Details.Suites.List), currentEndpoint.Details.Suites.Preference, currentEndpoint.Details.ServerSignature, currentEndpoint.Details.Key.DebianFlaw, currentEndpoint.Details.SessionResumption, currentEndpoint.Details.RenegSupport, currentEndpoint.Details.Chain.Issues, currentReport.EngineVersion, currentReport.CriteriaVersion, strings.Join(currentEndpoint.Details.Cert.CrlURIs, " "), strings.Join(currentEndpoint.Details.Cert.OcspURIs, " "), currentEndpoint.Details.VulnBeast, currentEndpoint.Details.CompressionMethods, currentEndpoint.Details.SupportsNpn, currentEndpoint.Details.NpnProtocols, currentEndpoint.Details.SessionTickets, currentEndpoint.Details.OcspStapling, currentEndpoint.Details.SniRequired, currentEndpoint.Details.HttpStatusCode, currentEndpoint.Details.HttpForwarding, currentEndpoint.Details.Key.Strength, sims, currentEndpoint.Details.ForwardSecrecy, currentEndpoint.Details.Heartbeat, currentEndpoint.Details.Heartbleed, currentEndpoint.Details.Poodle, currentEndpoint.Details.PoodleTls, currentEndpoint.Details.Logjam, currentEndpoint.Details.Freak, currentEndpoint.Details.OpenSslCcs, currentEndpoint.Details.DhYsReuse, currentEndpoint.Details.DhUsesKnownPrimes, strings.Join(currentEndpoint.Details.DhPrimes, ";"), currentEndpoint.Details.SupportsRc4, currentEndpoint.Details.Rc4WithModern, currentEndpoint.Details.DhUsesKnownPrimes, currentEndpoint.Details.HstsPolicy.MaxAge, currentEndpoint.Details.HstsPolicy.Header, currentEndpoint.Details.HstsPolicy.Status, currentEndpoint.Details.HstsPolicy.IncludeSubDomains, currentEndpoint.Details.HstsPolicy.Preload, hstsPolicyDirectives, string(hpkpPolicy), string(hpkpRoPolicy), currentEndpoint.Details.HasSct, chainPinSha256, chainSha1Hashes, currentEndpoint.Details.Rc4Only, currentEndpoint.Details.ChaCha20Preference, currentEndpoint.Details.DrownVulnerable, currentEndpoint.Details.Cert.MustStaple, currentEndpoint.Details.OpenSSLLuckyMinus20, currentReport.HeaderScore.Score, currentReport.HeaderScore.XFrameOptions, currentReport.HeaderScore.StrictTransportSecurity, currentReport.HeaderScore.XContentTypeOptions, currentReport.HeaderScore.XXSSProtection, currentReport.ObservatoryScan.Grade, observatoryPassFail, observatoryDescriptions)
		if err != nil {
			if logLevel >= LOG_ERROR {
				log.Printf("[ERROR] Error executing SQL-Transaction: %v", err)
			}
			tx.Rollback()
			db.Close()
			return err
		}
		if err == nil {
			fmt.Println(result.RowsAffected())
			tx.Commit()
		}
		db.Close()
	}
	return nil
}

func NewSqlAssessment(e Event, eventChannel chan Event) {
	e.senderID = "sql"
	e.eventType = INTERNAL_ASSESSMENT_STARTING
	eventChannel <- e
	maxRetries := globalSQLRetries

	for i := 0; i < maxRetries+1; i++ {
		timeout := (float32(i) + 1.0) * 0.5
		err := writeToDb(e.report)
		if err == nil {
			break
		}
		if i == maxRetries {
			log.Printf("[ERROR] Connection to SQL-Server failed after %v retries: %v", maxRetries, err)
			e.eventType = INTERNAL_ASSESSMENT_FAILED
			eventChannel <- e
			return
		}
		if logLevel >= LOG_INFO {
			log.Printf("[INFO] Connection to SQL-Server failed, retrying in %v seconds", timeout)
			return
		}
		time.Sleep(time.Duration(timeout) * time.Second)
	}
	e.eventType = INTERNAL_ASSESSMENT_COMPLETE
	eventChannel <- e
}

func (manager *Manager) startSqlAssessment(e Event) {
	go NewSqlAssessment(e, manager.InternalEventChannel)
	activeSqlAssessments++
}

func (manager *Manager) sqlRun() {
	moreSqlAssessments := true
	for {
		select {
		// Handle assessment events (e.g., starting and finishing).
		case e := <-manager.InternalEventChannel:
			if e.eventType == INTERNAL_ASSESSMENT_FAILED {
				activeSqlAssessments--
				log.Printf("[ERROR] sqlWrite for %v failed", e.host)
				//TODO ERROR handeling
			}

			if e.eventType == INTERNAL_ASSESSMENT_STARTING {
				if logLevel >= LOG_INFO {
					log.Printf("[INFO] sqlWrite starting: %v", e.host)
				}
			}

			if e.eventType == INTERNAL_ASSESSMENT_COMPLETE {
				if logLevel >= LOG_INFO {
					log.Printf("[INFO] sqlWrite for %v finished", e.host)
				}

				activeSqlAssessments--

				// We have a finished assessment now that we can add third-party information to
				// And we won't re-query these third partys by relying on the ssllabs-scan polling

				e.eventType = FINISHED
				e.senderID = "sql"
				manager.OutputEventChannel <- e

				if logLevel >= LOG_DEBUG {
					log.Printf("[DEBUG] Active assessments: %v (more: %v)", activeSqlAssessments, moreSqlAssessments)
				}
			}

			// Are we done?
			if (activeSqlAssessments == 0) && (moreSqlAssessments == false) {
				manager.finish("sql")
				return
			}

			break

		// Once a second, start a new assessment, provided there are
		// hostnames left and we're not over the concurrent assessment limit.
		default:
			<-time.NewTimer(time.Duration(100) * time.Millisecond).C

			if moreSqlAssessments {
				if activeSqlAssessments < maxSqlAssessments {
					e, running := <-manager.InputEventChannel
					if running {
						manager.startSqlAssessment(e)
					} else {
						// We've run out of hostnames and now just need
						// to wait for all the assessments to complete.
						moreSqlAssessments = false

						if activeSqlAssessments == 0 {
							manager.finish("sql")
							return
						}
					}
				}
			}
			break
		}
	}
}
