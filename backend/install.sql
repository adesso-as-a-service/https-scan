/*****************************************************************************/
/*****                     CREATE TABLE CertificatesV10                     **/
/*****************************************************************************/

create table CertificatesV10
(
	ThumbprintSHA256 nvarchar(80) not null
		constraint PK_CertificatesV10
			primary key,
	ThumbprintSHA1 nchar(40) not null,
	CommonNames nvarchar(max),
	AltNames nvarchar(max),
	SerialNumber nvarchar(100),
	Subject nvarchar(300),
	IssuerSubject nvarchar(300),
	SigAlg nvarchar(30),
	RevocationStatus tinyint,
	Issues smallint,
	KeyStrength smallint,
	DebianInsecure bit,
	NextThumbprint nchar(40),
	ValidFrom datetime,
	ValidTo datetime,
	CreatedAt datetime not null,
	UpdatedAt datetime not null
)
go

/*****************************************************************************/
/*****                     CREATE TABLE CertificateChainsV10                **/
/*****************************************************************************/

create table CertificateChainsV10
(
	ThumbprintSHA256 nvarchar(80) not null
		constraint FK_CertificateChainsV10_CertificatesV10_ThumbprintSHA256
			references CertificatesV10,
	NextThumbprintSHA256 nvarchar(80) not null
		constraint FK_CertificateChainsV10_CertificatesV10_NextThumbprintSHA256
			references CertificatesV10,
	CreatedAt datetime,
	UpdatedAt datetime,
	constraint PK_CertificateChainsV10
		primary key (ThumbprintSHA256, NextThumbprintSHA256)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE Customer                            **/
/*****************************************************************************/

create table Customer
(
	ID int identity
		constraint PK_Customer
			primary key,
	Name nvarchar(50) not null
)
go

/*****************************************************************************/
/*****                     CREATE TABLE Domains                             **/
/*****************************************************************************/

create table Domains
(
	DomainID int identity
		constraint PK_Domains
			primary key,
	DomainName nvarchar(100) not null,
	ListID nvarchar(50),
	isActive bit not null,
	nextScan bit not null,
	CreationDate datetime2 not null,
	CustomerID int,
	DeactivationDate datetime2,
	Comment varchar(100),
	isCdn bit not null
)
go

/*****************************************************************************/
/*****                     CREATE TABLE Project                             **/
/*****************************************************************************/

create table Project
(
	ID int identity
		constraint PK_Project
			primary key,
	Name nvarchar(250) not null,
	Email nvarchar(100) not null,
	CiresTeamID int,
	CustomerID int
		constraint FK_Project_Customer
			references Customer,
	MinimumRequirement varchar(1000)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE Domain_Project                      **/
/*****************************************************************************/

create table Domain_Project
(
	DomainID int not null
		constraint FK_Teams_Domains
			references Domains,
	ProjectID int not null
		constraint FK_Teams_Project
			references Project,
	CiresDomainID int,
	constraint PK_Domain_Project
		primary key (DomainID, ProjectID)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE Scans                               **/
/*****************************************************************************/

create table Scans
(
	ScanID int identity
		constraint PK_Scans
			primary key,
	SSLLabs bit not null,
	SSLLabsVersion nvarchar(4),
	Observatory bit not null,
	ObservatoryVersion nvarchar(4),
	SecurityHeaders bit not null,
	SecurityHeadersVersion nvarchar(4),
	Crawler bit not null,
	CrawlerVersion nvarchar(4),
	Unreachable int,
	Total int,
	Done bit not null,
	StartTime datetime2(2) not null,
	Config nvarchar(2000)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE CrawlerV10                          **/
/*****************************************************************************/

create table CrawlerV10
(
	ScanID int not null
		constraint FK_CrawlerV10_Scans
			references Scans,
	DomainID int not null
		constraint FK_CrawlerV10_Domains
			references Domains,
	DomainReachable tinyint not null,
	TestWithSSL bit not null,
	Redirects smallint,
	StatusCodes nvarchar(50),
	URLs nvarchar(1000),
	ScanStatus tinyint not null,
	LastStatusCode smallint,
	LastURL nvarchar(200),
	IP nvarchar(30),
	RetriesStatuscode tinyint,
	constraint PK_CrawlerV10
		primary key (ScanID, DomainID, TestWithSSL)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE ObservatoryTLSV10                   **/
/*****************************************************************************/

create table ObservatoryTLSV10
(
	ScanID int not null
		constraint ObservatoryTLSV10_Scans_ScanID_fk
			references Scans,
	DomainID int not null
		constraint ObservatoryTLSV10_Domains_DomainID_fk
			references Domains,
	TestWithSSL bit not null,
	DomainReachable tinyint not null,
	ScanStatus tinyint not null,
	Target nvarchar(200),
	ObsScanID int,
	EndTime datetime,
	MozillaEvaluationWorker_Level nvarchar(50),
	MozillaGradingWorker_Grade real,
	MozillaGradingWorker_Lettergrade char,
	Cert_CommonName nvarchar(255),
	Cert_AlternativeNames text,
	Cert_FirstObserved datetime,
	Cert_ValidFrom datetime,
	Cert_ValidTo datetime,
	Cert_Key nvarchar(100),
	Cert_Issuer nvarchar(100),
	Cert_SignatureKeyAlgorithm nvarchar(100),
	HasCAARecord bit,
	ServerSideCipherOrdering bit,
	OCSPStapling bit,
	constraint ObservatoryTLSV10_pk
		primary key nonclustered (ScanID, DomainID, TestWithSSL)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE ObservatoryV10                      **/
/*****************************************************************************/

create table ObservatoryV10
(
	ScanID int not null
		constraint FK_ObservatoryV10_Scans
			references Scans,
	DomainID int not null
		constraint FK_ObservatoryV10_Domains
			references Domains,
	TestWithSSL bit not null,
	DomainReachable tinyint not null,
	ScanStatus tinyint not null,
	Grade nchar(2),
	Score tinyint,
	TestsFailed tinyint,
	TestsPassed tinyint,
	TestsQuantity tinyint,
	CSPPassed bit,
	CSPEval smallint,
	CSPResult nvarchar(100),
	CSPDesc nvarchar(250),
	CookiesPassed bit,
	CookiesResult nvarchar(100),
	CookiesDesc nvarchar(250),
	CORSPassed bit,
	CORSResult nvarchar(100),
	CORSDesc nvarchar(250),
	HPKPPassed bit,
	HPKPResult nvarchar(100),
	HPKPDesc nvarchar(250),
	RedirectionPassed bit,
	RedirectionResult nvarchar(100),
	RedirectionDesc nvarchar(250),
	HSTSPassed bit,
	HSTSResult nvarchar(100),
	HSTSDesc nvarchar(250),
	SRIPassed bit,
	SRIResult nvarchar(100),
	SRIDesc nvarchar(250),
	XContentTypePassed bit,
	XContentTypeResult nvarchar(100),
	XContentTypeDesc nvarchar(250),
	XXSSProtectionPassed bit,
	XXSSProtectionResult nvarchar(100),
	XXSSProtectionDesc nvarchar(250),
	XFrameOptionsPassed bit,
	XFrameOptionsResult nvarchar(100),
	XFrameOptionsDesc nvarchar(250),
	ReferrerPolicyPassed bit,
	ReferrerPolicyDesc nchar(100),
	ReferrerPolicyResult nchar(250),
	constraint PK_ObservatoryV10
		primary key (ScanID, DomainID, TestWithSSL)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE SSLLabsV10                          **/
/*****************************************************************************/

create table SSLLabsV10
(
	ScanID int not null
		constraint FK_SSLLabsV10_Scans
			references Scans,
	DomainID int not null
		constraint FK_SSLLabsV10_Domains
			references Domains,
	TestWithSSL bit not null,
	DomainReachable tinyint not null,
	ScanStatus tinyint not null,
	IP nvarchar(30),
	Grade nvarchar(2),
	GradeTrustIgnored nvarchar(2),
	FutureGrade nvarchar(2),
	HasWarnings bit,
	IsExceptional bit,
	NumberWeakProtocols int,
	WeakProtocols nvarchar(50),
	NumberProtocols int,
	Protocols nvarchar(50),
	NumberWeakSuites int,
	WeakSuites nvarchar(2000),
	NumberSuites int,
	Suites nvarchar(4000),
	ForwardSecrecy tinyint,
	RenegSupport tinyint,
	SupportsRC4 bit,
	VulnBeast bit,
	VulnHeartbleed bit,
	VulnOpenSslCcs smallint,
	VulnOpenSSLLuckyMinus20 smallint,
	VulnTicketbleed tinyint,
	VulnBleichenbacher smallint,
	VulnPoodle tinyint,
	VulnFreak bit,
	VulnLogjam bit,
	VulnDrown bit,
	DhUsesKnownPrimes tinyint,
	DhYsReuse bit,
	EcdhParameterReuse bit,
	CertificateChainIssues smallint,
	CertificateChainLength tinyint,
	EndEntityCertificateThumbprint nchar(40),
	StartTime datetime,
	TestTime datetime,
	constraint PK_SSLLabsV10
		primary key (ScanID, DomainID, TestWithSSL)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE SecurityHeadersV10                  **/
/*****************************************************************************/

create table SecurityHeadersV10
(
	ScanID int not null
		constraint FK_SecurityHeadersV10_Scans
			references Scans,
	DomainID int not null
		constraint FK_SecurityHeadersV10_Domains
			references Domains,
	TestWithSSL bit not null,
	DomainReachable tinyint not null,
	ScanStatus int not null,
	Grade nchar(2),
	XFrameOptions nvarchar(300),
	StrictTransportSecurity nvarchar(300),
	XContentTypeOptions nvarchar(300),
	XXSSProtection nvarchar(300),
	ContentSecurityPolicy nvarchar(max),
	ReferrerPolicy nvarchar(300),
	FeaturePolicy nvarchar(300),
	ExpectCT nvarchar(300),
	ReportTo nvarchar(300),
	NEL nvarchar(300),
	constraint PK_SecurityHeadersV10
		primary key (ScanID, DomainID, TestWithSSL)
)
go

/*****************************************************************************/
/*****                     CREATE TABLE Unreachable                         **/
/*****************************************************************************/

create table Unreachable
(
	ScanID int not null,
	DomainID int not null,
	DNSError bit not null,
	constraint PK_Unreachable
		primary key (ScanID, DomainID)
)
go
