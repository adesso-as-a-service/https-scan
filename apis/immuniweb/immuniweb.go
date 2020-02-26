package example

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/fatih/structs"

	"../../backend"
	"../../hooks"
)

// TableRow represents the scan results for the immuniweb table
type TableRow struct {
	// TableRows
	ScanStatus int
	Score int
	Grade string
	ShortID string
	ScoresNistDescription string
	ScoresNistClass string
	ScoresHipaaDescription string
	ScoresHipaaClass string
	ScoresPcidssDescription string
	ScoresPcidssClass string
	ScoresBestPracticesDescription string
	ScoresBestPracticesClass string
	ServerSignature string
	HasPcidssCertSmallKey bool
	HasPcidssCertWeakSignature bool
	HasPcidssCertTrusted bool
	PcidssSupportedSuites string
	PcidssSupportsTLS10 bool
	PcidssSupportsTLS11 bool
	PcidssSupportsTLS12 bool
	PcidssSupportsTLS13 bool
	HasPcidssInvalidProtocols bool
	HasPcidssInvalidSuites bool
	HasPcidssSupportedElipticCurves bool
	PcidssSupportedCurves string
	HasPcidssInvalidCurves bool
	IsPcidssDrownAffected bool
	IsPcidssPoodleSSLAffected bool
	IsPcidssPoodlTLSAffected bool
	IsPcidssGoldendoodleAffected string
	IsPcidssZombiePoodleAffected bool
	IsPcidssSleepingPoodleAffected bool
	IsPcidss0lengthOpensslAffected bool
	IsPcidssCve20162107Affected bool
	IsPcidssSupportsInsecureRenegAffected bool
	IsPcidssRobotAffected bool
	IsPcidssHeartbleedAffected bool
	IsPcidssCve20140224Affected bool
	IsPcidssCompliant bool
	HasHipaaCertX509V3 bool
	IsHipaaCertSelfSigned bool
	HasHipaaCertProvidesRevocationInformation bool
	HasHipaaCertSmallKey bool
	HasHipaaCertSignatureAlgorithmMismatch bool
	HasHipaaCertWeakSignature bool
	HipaaSupportsOcspStapling bool
	HipaaSupportedProtocolsTLS10 bool
	HipaaSupportedProtocolsTLS11 bool
	HipaaSupportedProtocolsTLS12 bool
	HipaaSupportedProtocolsTLS13 bool
	HipaaSupportsInvalidProtocols bool
	HipaaSupportsInvalidCipherSuites bool
	HipaaSupportedCipherSuites string
	HasHipaaSupportedEllipticCurves
	HipaaSupportedEllipticCurves string
	HipaaSupportsInvalidCurves bool
	HipaaSupportsMandatoryCurves bool
	HipaaMissingMandatoryCiphers string
	HasHipaaAllMandatoryCiphers bool
	HasHipaaProvidesRenegInformation bool
	HasHipaaEcPointFormat bool
	HipaaHipaaCompliant bool
	HasNistCertX509V3 bool
	IsNistCertSelfSigned bool
	HasNistCertProvidesRevocationInformation bool
	HasNistCertSmallKey bool
	HasNistCertSignatureAlgorithmMismatch bool
	HasNistCertWeakSignature bool
	NistSupportsOcspStapling bool
	NistSupportedProtocolsTLS10 bool
	NistSupportedProtocolsTLS11 bool
	NistSupportedProtocolsTLS12 bool
	NistSupportedProtocolsTLS13 bool
	NistSupportsInvalidProtocols bool
	NistSupportsInvalidCipherSuites bool
	NistSupportedCipherSuites string
	HasNistSupportedEllipticCurves bool
	NistSupportedEllipticCurves String bool
	NistSupportsInvalidCurves bool
	NistSupportsMandatoryCurves bool
	NistMissingMandatoryCiphers string
	HasNistAllMandatoryCiphers bool
	HasNistProvidesRenegInformation bool
	HasNistEcPointFormat bool
	NistNistCompliant bool
	HasBestPracticesDnsCaa bool
	BestPracticesDnsCaa bool
	HasBestPracticesEarlyData bool
	IsBestPracticesCertValidTooLong bool
	HasBestPracticesCertEv bool
	BestPracticesSupportsTlsv13 bool
	HasBestPracticesPreference bool
	BestPracticesCipherPreference bool
	IsBestPracticesPrefersWeakCipher bool
	IsBestPracticesPrefersPfs bool
	HasBestPracticesHttpToHttpsRedirect bool
	HasBestPracticesMixedContent bool
	HasBestPracticesHasHsts bool
	HasBestPracticesHstsDuration bool
	HasBestPracticesHstsLong bool
	HasBestPracticesHpkp bool
	HasBestPracticesSupportsFallbackScsv bool
	HasBestPracticesSupportsClientInitiatedReneg bool
	HasBestPracticesSupportsSecureReneg bool
	HasBestPracticesTlsCompression bool
}

// maxRedirects sets the maximum number of Redirects to be followed
var maxRedirects int

var maxScans int

var used *bool

var maxRetries *int

// exampleVersion
var version = "10"

// exampleManager
var manager = hooks.Manager{
	MaxRetries:       3,        //Max Retries
	MaxParallelScans: maxScans, //Max parallel Scans
	Version:          version,
	Table:            "ImmuniwebResult",           //Table name
	ScanType:         hooks.ScanOnlySSL,         // Scan HTTP or HTTPS   // @IMU
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
	Hidden        bool     // @IMU
	APILocation   string   // @IMU
}

// defaultConfig
var currentConfig = Config{
	Retries:       3,
	ScanType:      hooks.ScanOnlySSL, // @IMU
	ParallelScans: 5, // @IMU
	LogLevel:      "info",
	APILocation:   "KOMMT NUOCH", // @IMU
	Hidden:        true  // @IMU
}

type ImmuniwebApiResult struct {
	ServerInfo struct {
		IP struct {
			Value string `json:"value"`
			Tag   int    `json:"tag"`
		} `json:"ip"`
		Port struct {
			Value int `json:"value"`
			Tag   int `json:"tag"`
		} `json:"port"`
		IsPortOpen struct {
			Value bool `json:"value"`
			Tag   int  `json:"tag"`
		} `json:"is_port_open"`
		Hostname struct {
			Value string `json:"value"`
			Tag   int    `json:"tag"`
		} `json:"hostname"`
		ReverseDNS struct {
			Value string `json:"value"`
			Tag   int    `json:"tag"`
		} `json:"reverse_dns"`
		HTTPResponse struct {
			Value string `json:"value"`
			Tag   int    `json:"tag"`
		} `json:"http_response"`
		ServerSignature struct {
			Value string `json:"value"`
			Tag   int    `json:"tag"`
		} `json:"server_signature"`
		Protocol struct {
			Tag   int    `json:"tag"`
			Value string `json:"value"`
		} `json:"protocol"`
	} `json:"server_info"`
	Certificates struct {
		Information []struct {
			KeyType               string `json:"key_type"`
			KeySize               int    `json:"key_size"`
			SignatureAlgorithm    string `json:"signature_algorithm"`
			IssuerCn              string `json:"issuer_cn"`
			Cn                    string `json:"cn"`
			O                     string `json:"o"`
			San                   string `json:"san"`
			Transparency          bool   `json:"transparency"`
			Ev                    bool   `json:"ev"`
			Validation            string `json:"validation"`
			ValidFrom             int    `json:"valid_from"`
			ValidTo               int    `json:"valid_to"`
			ValidNow              bool   `json:"valid_now"`
			ExpiresSoon           bool   `json:"expires_soon"`
			OcspMustStaple        bool   `json:"ocsp_must_staple"`
			SupportsOcspStapling  bool   `json:"supports_ocsp_stapling"`
			SelfSigned            bool   `json:"self_signed"`
			ValidForHost          bool   `json:"valid_for_host"`
			Revoked               bool   `json:"revoked"`
			KnownIssuer           bool   `json:"known_issuer"`
			RevocationInformation struct {
				Ocsp struct {
					URL     string `json:"url"`
					Revoked bool   `json:"revoked"`
					Error   bool   `json:"error"`
				} `json:"ocsp"`
				Crl struct {
					URL     string `json:"url"`
					Revoked bool   `json:"revoked"`
					Error   bool   `json:"error"`
				} `json:"crl"`
			} `json:"revocation_information"`
			Trusted bool `json:"trusted"`
		} `json:"information"`
		ChainInstallationIssues []struct {
			Value   bool `json:"value"`
			Results struct {
				IsChainComplete struct {
					Value     bool `json:"value"`
					MessageID int  `json:"message_id"`
					Tag       int  `json:"tag"`
				} `json:"is_chain_complete"`
				HasSentRootCa struct {
					Value     bool `json:"value"`
					MessageID int  `json:"message_id"`
					Tag       int  `json:"tag"`
				} `json:"has_sent_root_ca"`
				IsOrderCorrect struct {
					Value     bool `json:"value"`
					MessageID int  `json:"message_id"`
					Tag       int  `json:"tag"`
				} `json:"is_order_correct"`
				HasSentExtraCerts struct {
					Value     bool `json:"value"`
					MessageID int  `json:"message_id"`
					Tag       int  `json:"tag"`
				} `json:"has_sent_extra_certs"`
			} `json:"results"`
		} `json:"chain_installation_issues"`
		Chains [][]struct {
			DataPem                string `json:"data_pem"`
			Sha256                 string `json:"sha256"`
			Cn                     string `json:"cn"`
			KeyType                string `json:"key_type"`
			KeySize                int    `json:"key_size"`
			SignatureAlgorithm     string `json:"signature_algorithm"`
			ValidTo                int    `json:"valid_to"`
			ValidFrom              int    `json:"valid_from"`
			Pin                    string `json:"pin"`
			MatchesHpkp            bool   `json:"matches_hpkp"`
			CertType               string `json:"cert_type"`
			Comment                string `json:"comment"`
			WeakKeySize            bool   `json:"weak_key_size"`
			WeakSignatureAlgorithm bool   `json:"weak_signature_algorithm"`
		} `json:"chains"`
		Graphs [][]struct {
			DataPem                string   `json:"data_pem"`
			Sha256                 string   `json:"sha256"`
			Cn                     string   `json:"cn"`
			KeyType                string   `json:"key_type"`
			KeySize                int      `json:"key_size"`
			SignatureAlgorithm     string   `json:"signature_algorithm"`
			ValidTo                int      `json:"valid_to"`
			ValidFrom              int      `json:"valid_from"`
			Pin                    string   `json:"pin"`
			MatchesHpkp            bool     `json:"matches_hpkp"`
			CertType               string   `json:"cert_type"`
			Comment                string   `json:"comment"`
			WeakKeySize            bool     `json:"weak_key_size"`
			WeakSignatureAlgorithm bool     `json:"weak_signature_algorithm"`
			ChildrenHashes         []string `json:"children_hashes"`
			TreeLevels             []int    `json:"tree_levels"`
		} `json:"graphs"`
	} `json:"certificates"`
	Nist struct {
		CertX509V3 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_x509_v3"`
		CertSelfSigned struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_self_signed"`
		CertProvidesRevocationInformation struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_provides_revocation_information"`
		CertSmallKey struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_small_key"`
		CertSignatureAlgorithmMismatch struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_signature_algorithm_mismatch"`
		CertWeakSignature struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_weak_signature"`
		SupportsOcspStapling struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_ocsp_stapling"`
		SupportedCipherSuites []struct {
			Value     string   `json:"value"`
			Tag       int      `json:"tag"`
			Protocols []string `json:"protocols"`
		} `json:"supported_cipher_suites"`
		SupportedProtocols []struct {
			Value string `json:"value"`
			Tag   int    `json:"tag"`
		} `json:"supported_protocols"`
		SupportsInvalidProtocols struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_protocols"`
		SupportsInvalidCipherSuites struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_cipher_suites"`
		SupportedEllipticCurves []struct {
			Value string `json:"value"`
			Size  int    `json:"size"`
			Tag   int    `json:"tag"`
		} `json:"supported_elliptic_curves"`
		SupportsInvalidCurves struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_curves"`
		SupportsMandatoryCurves struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_mandatory_curves"`
		SupportsTlsv11 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_tlsv1.1"`
		SupportsTlsv12 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_tlsv1.2"`
		SupportsTlsv13 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_tlsv1.3"`
		MissingMandatoryCiphers []interface{} `json:"missing_mandatory_ciphers"`
		HasAllMandatoryCiphers  struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"has_all_mandatory_ciphers"`
		ProvidesRenegInformation struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"provides_reneg_information"`
		EcPointFormat struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"ec_point_format"`
		Compliant struct {
			Value bool `json:"value"`
		} `json:"compliant"`
	} `json:"nist"`
	Hipaa struct {
		CertX509V3 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_x509_v3"`
		CertSelfSigned struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_self_signed"`
		CertProvidesRevocationInformation struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_provides_revocation_information"`
		CertSmallKey struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_small_key"`
		CertSignatureAlgorithmMismatch struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_signature_algorithm_mismatch"`
		CertWeakSignature struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_weak_signature"`
		SupportsOcspStapling struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_ocsp_stapling"`
		SupportedProtocols []struct {
			Value string `json:"value"`
			Tag   int    `json:"tag"`
		} `json:"supported_protocols"`
		SupportsInvalidProtocols struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_protocols"`
		SupportsInvalidCipherSuites struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_cipher_suites"`
		SupportedCipherSuites []struct {
			Value     string   `json:"value"`
			Tag       int      `json:"tag"`
			Protocols []string `json:"protocols"`
		} `json:"supported_cipher_suites"`
		SupportedEllipticCurves []struct {
			Value string `json:"value"`
			Size  int    `json:"size"`
			Tag   int    `json:"tag"`
		} `json:"supported_elliptic_curves"`
		SupportsInvalidCurves struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_curves"`
		SupportsMandatoryCurves struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_mandatory_curves"`
		SupportsTlsv11 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_tlsv1.1"`
		SupportsTlsv12 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_tlsv1.2"`
		SupportsTlsv13 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_tlsv1.3"`
		MissingMandatoryCiphers []interface{} `json:"missing_mandatory_ciphers"`
		HasAllMandatoryCiphers  struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"has_all_mandatory_ciphers"`
		ProvidesRenegInformation struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"provides_reneg_information"`
		EcPointFormat struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"ec_point_format"`
		Compliant struct {
			Value bool `json:"value"`
		} `json:"compliant"`
	} `json:"hipaa"`
	PciDss struct {
		CertSmallKey struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_small_key"`
		CertWeakSignature struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_weak_signature"`
		CertTrusted struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_trusted"`
		SupportedCipherSuites []struct {
			Value     string   `json:"value"`
			Tag       int      `json:"tag"`
			Protocols []string `json:"protocols"`
		} `json:"supported_cipher_suites"`
		SupportedProtocols []struct {
			Value string `json:"value"`
			Tag   int    `json:"tag"`
		} `json:"supported_protocols"`
		SupportsInvalidProtocols struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_protocols"`
		SupportsInvalidCipherSuites struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_cipher_suites"`
		SupportedEllipticCurves []struct {
			Value string `json:"value"`
			Size  int    `json:"size"`
			Tag   int    `json:"tag"`
		} `json:"supported_elliptic_curves"`
		SupportsInvalidCurves struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_invalid_curves"`
		Drown struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"drown"`
		PoodleSsl struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"poodle_ssl"`
		PoodleTLS struct {
			Value         int  `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"poodle_tls"`
		Goldendoodle struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"goldendoodle"`
		ZombiePoodle struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"zombie_poodle"`
		SleepingPoodle struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"sleeping_poodle"`
		ZeroLengthOpenssl struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"0length_openssl"`
		Cve20162107 struct {
			Value         int  `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cve_2016_2107"`
		SupportsInsecureReneg struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_insecure_reneg"`
		Robot struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"robot"`
		Heartbleed struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"heartbleed"`
		Cve20140224 struct {
			Value         int  `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cve_2014_0224"`
		Compliant struct {
			Value bool `json:"value"`
		} `json:"compliant"`
	} `json:"pci_dss"`
	IndustryBestPractices struct {
		Dnscaa struct {
			Value struct {
				Value         []interface{} `json:"value"`
				Tag           int           `json:"tag"`
				TitleID       int           `json:"title_id"`
				MessageID     int           `json:"message_id"`
				DescriptionID int           `json:"description_id"`
				Visible       bool          `json:"visible"`
			} `json:"value"`
			Tag           int  `json:"tag"`
			TitleID       int  `json:"title_id"`
			MessageID     int  `json:"message_id"`
			DescriptionID int  `json:"description_id"`
			Visible       bool `json:"visible"`
		} `json:"dnscaa"`
		EarlyData struct {
			Value         bool `json:"value"`
			Tag           int  `json:"tag"`
			TitleID       int  `json:"title_id"`
			MessageID     int  `json:"message_id"`
			DescriptionID int  `json:"description_id"`
			Visible       bool `json:"visible"`
		} `json:"early_data"`
		CertValidTooLong struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_valid_too_long"`
		CertEv struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"cert_ev"`
		SupportsTlsv13 struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_tlsv1.3"`
		HasPreference struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"has_preference"`
		CipherPreference []struct {
			Protocol string `json:"protocol"`
			Value    string `json:"value"`
			Tag      int    `json:"tag"`
		} `json:"cipher_preference"`
		PrefersWeakCipher struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"prefers_weak_cipher"`
		PrefersPfs struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"prefers_pfs"`
		HTTPToHTTPSRedirect struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"http_to_https_redirect"`
		MixedContent struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"mixed_content"`
		HasHsts struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"has_hsts"`
		HstsDuration struct {
			Value         int  `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"hsts_duration"`
		HstsLong struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"hsts_long"`
		HasHpkp struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"has_hpkp"`
		SupportsFallbackScsv struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_fallback_scsv"`
		SupportsClientInitiatedReneg struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_client_initiated_reneg"`
		SupportsSecureReneg struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"supports_secure_reneg"`
		TLSCompression struct {
			Value         bool `json:"value"`
			MessageID     int  `json:"message_id"`
			Tag           int  `json:"tag"`
			DescriptionID int  `json:"description_id"`
			TitleID       int  `json:"title_id"`
			Visible       bool `json:"visible"`
		} `json:"tls_compression"`
	} `json:"industry_best_practices"`
	Email             []interface{} `json:"email"`
	ThirdPartyContent []interface{} `json:"third_party_content"`
	Results           struct {
		Score         int    `json:"score"`
		Grade         string `json:"grade"`
		IsBlacklisted bool   `json:"is_blacklisted"`
		HasSslTLS     bool   `json:"has_ssl_tls"`
	} `json:"results"`
	Highlights []struct {
		HighlightID int `json:"highlight_id"`
		Tag         int `json:"tag"`
	} `json:"highlights"`
	WID       string `json:"w_id"`
	PageTitle string `json:"page_title"`
	Gdpr      struct {
		Compliant bool `json:"compliant"`
		Check1    bool `json:"check_1"`
		Check2    bool `json:"check_2"`
	} `json:"gdpr"`
	CompanyName string `json:"company_name"`
	Internals   struct {
		ID                 string `json:"id"`
		ShortID            string `json:"short_id"`
		ShowTestResults    bool   `json:"show_test_results"`
		Lat                string `json:"lat"`
		Lng                string `json:"lng"`
		Ts                 int    `json:"ts"`
		Errors             int    `json:"errors"`
		GradeNorm          string `json:"grade_norm"`
		Title              string `json:"title"`
		Heading            string `json:"heading"`
		ServerIPPort       string `json:"server_ip_port"`
		Location           string `json:"location"`
		Country            string `json:"country"`
		Protocol           string `json:"protocol"`
		TitleTwitter       string `json:"title_twitter"`
		ServerLocation     string `json:"server_location"`
		CanIndex           bool   `json:"can_index"`
		DescriptionTwitter string `json:"description_twitter"`
		Description        string `json:"description"`
		Scores             struct {
			Nist struct {
				Description string `json:"description"`
				Class       string `json:"class"`
			} `json:"nist"`
			Hipaa struct {
				Description string `json:"description"`
				Class       string `json:"class"`
			} `json:"hipaa"`
			PciDss struct {
				Description string `json:"description"`
				Class       string `json:"class"`
			} `json:"pci_dss"`
			IndustryBestPractices struct {
				Description string `json:"description"`
				Class       string `json:"class"`
			} `json:"industry_best_practices"`
		} `json:"scores"`
	} `json:"internals"`
}

// AnalyzeResult is the object to contain the response we get
// From starting an Immuniweb result
type ImmuniwebApiResult struct {
	EndTime         string `json:"end_time"`
	Grade           string `json:"grade"`
	ResponseHeaders struct {
		CacheControl     string `json:"Cache-Control"`
		Connection       string `json:"Connection"`
		ContentType      string `json:"Content-Type"`
		Date             string `json:"Date"`
		Expires          string `json:"Expires"`
		Server           string `json:"Server"`
		TransferEncoding string `json:"Transfer-Encoding"`
	} `json:"response_headers"`
	ScanID        int    `json:"scan_id"`
	Score         int    `json:"score"`
	StartTime     string `json:"start_time"`
	State         string `json:"state"`
	TestsFailed   int    `json:"tests_failed"`
	TestsPassed   int    `json:"tests_passed"`
	TestsQuantity int    `json:"tests_quantity"`
}



/* ------------------------------------------------------------
			             !!! TODO !!!

	'handleScan' starts a new assessment if there is room for
	another parallel assessment.

	1. If needed add a custom assessment start conditions.
	   Normally an assessment is started when the number of
	   current scans is lower than the number of allowed
	   parallel scans.

------------------------------------------------------------ */

// @IMU muss glaube ich nicht bearbeitet werden (auch nicht beom obervatory)
func handleScan(domains []hooks.DomainsReachable, internalChannel chan hooks.InternalMessage) []hooks.DomainsReachable {
	for (len(manager.Errors) > 0 || len(domains) > 0) && int(manager.Status.GetCurrentScans()) < manager.MaxParallelScans {
		manager.FirstScan = true
		var scanMsg hooks.InternalMessage
		var retDom = domains
		var scan hooks.DomainsReachable
		// pop fist domain
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

/* ------------------------------------------------------------
			             !!! TODO !!!

	'handleResults' saves the results of an assessment in the
	database.

	1. If the results returned from the assessment have to
	   handled specially, add the code here.

------------------------------------------------------------ */

// @IMU muss glaube ich nicht bearbeitet werden (auch nicht beom obervatory)
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

/* ------------------------------------------------------------
			             !!! TODO !!!

	'assessment' contains the assessment procedureand returns
	the results on the 'internalChannel'. Add the assessment-
	logic here

------------------------------------------------------------ */

func assessment(scan hooks.InternalMessage, internalChannel chan hooks.InternalMessage) {
	analyze, err := invokeImmuniwebAnalyzation(scan.Domain.DomainName)
	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't start scan for %v: %v", scan.Domain.DomainName, err), manager.LogLevel, hooks.LogError)
		scan.Results = TableRow{}
		scan.StatusCode = hooks.InternalError
		internalChannel <- scan
		return
	}

	results, err := invokeImmuniwebResults(analyze)

	if err != nil {
		hooks.LogIfNeeded(manager.Logger, fmt.Sprintf("Couldn't get results from API for %v: %v", scan.Domain.DomainName, err), manager.LogLevel, hooks.LogError)
		scan.Results = TableRow{}
		scan.StatusCode = hooks.InternalError
		internalChannel <- scan
		return
	}

	row := parseResult(results, analyze)

	scan.Results = row
	scan.StatusCode = hooks.InternalSuccess
	internalChannel <- scan
}

func invokeImmuniwebAnalyzation(domain string)
{
	
}

func invokeImmuniwebResults(string domain)
{
	
}




// @IMU 
func flagSetUp() {
	used = flag.Bool("no-Immuniweb", false, "Don't use the Immuniweb-API")
}

// @IMU 
func configureSetUp(currentScan *hooks.ScanRow, channel chan hooks.ScanStatusMessage, config interface{}) bool {
	currentScan.Immuniweb = !*used
	currentScan.ImmuniwebVersion = manager.Version
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
	manager.Logger = log.New(hooks.LogWriter, "Crawler\t", log.Ldate|log.Ltime)
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
