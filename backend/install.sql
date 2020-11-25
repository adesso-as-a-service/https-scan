/*****************************************************************************/
/*****                     CREATE TABLE Scans                               **/
/*****************************************************************************/

CREATE TABLE [dbo].[Scans]
(
    [ScanID]                 [int] IDENTITY (1,1) NOT NULL,
    [SSLLabs]                [bit]                NOT NULL,
    [SSLLabsVersion]         [nvarchar](4)        NULL,
    [Observatory]            [bit]                NOT NULL,
    [ObservatoryVersion]     [nvarchar](4)        NULL,
    [SecurityHeaders]        [bit]                NOT NULL,
    [SecurityHeadersVersion] [nvarchar](4)        NULL,
    [Crawler]                [bit]                NOT NULL,
    [CrawlerVersion]         [nvarchar](4)        NULL,
    [Unreachable]            [int]                NULL,
    [Total]                  [int]                NULL,
    [Done]                   [bit]                NOT NULL,
    [StartTime]              [datetime2](2)       NOT NULL,
    [Config]                 [nvarchar](2000)     NULL,
    CONSTRAINT [PK_Scans] PRIMARY KEY CLUSTERED
        (
         [ScanID] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[Scans]
    ADD CONSTRAINT [DF_Scans_StartTime] DEFAULT (getdate()) FOR [StartTime]
GO


/*****************************************************************************/
/*****                     CREATE TABLE Domains                             **/
/*****************************************************************************/

CREATE TABLE [dbo].[Domains]
(
    [DomainID]        [int] IDENTITY (1,1) NOT NULL,
    [DomainName]      [nvarchar](100)      NOT NULL,
    [ListID]          [nvarchar](50)       NULL,
    [isActive]        [bit]                NOT NULL,
    [nextScan]        [bit]                NOT NULL,
    [CreationDate]    [datetime2](7)       NOT NULL,
    [CustomerID]      [int]                NULL,
    [DeactivatedDate] [datetime2](7)       NULL,
    [Comment]         [varchar](100)       NULL,
    [isCdn]           [bit]                NOT NULL,
    CONSTRAINT [PK_Domains] PRIMARY KEY CLUSTERED
        (
         [DomainID] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[Domains]
    ADD DEFAULT ((1)) FOR [isActive]
GO

ALTER TABLE [dbo].[Domains]
    ADD DEFAULT ((0)) FOR [nextScan]
GO

ALTER TABLE [dbo].[Domains]
    ADD DEFAULT (sysdatetime()) FOR [CreationDate]
GO

ALTER TABLE [dbo].[Domains]
    ADD CONSTRAINT [DF_Domains_isCdn] DEFAULT ((0)) FOR [isCdn]
GO


/*****************************************************************************/
/*****                     CREATE TABLE Customer                            **/
/*****************************************************************************/

CREATE TABLE [dbo].[Customer]
(
    [ID]   [int] IDENTITY (1,1) NOT NULL,
    [Name] [nvarchar](50)       NOT NULL,
    CONSTRAINT [PK_Customer] PRIMARY KEY CLUSTERED
        (
         [ID] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO


/*****************************************************************************/
/*****                     CREATE TABLE Project                             **/
/*****************************************************************************/

CREATE TABLE [dbo].[Project]
(
    [ID]          [int] IDENTITY (1,1) NOT NULL,
    [Name]        [nvarchar](250)      NOT NULL,
    [Email]       [nvarchar](100)      NOT NULL,
    [CiresTeamID] [int]                NULL,
    [CustomerID]  [int]                NULL,
    CONSTRAINT [PK_Project] PRIMARY KEY CLUSTERED
        (
         [ID] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[Project]
    ADD CONSTRAINT [DF_Project_CustomerID] DEFAULT ((2)) FOR [CustomerID]
GO

ALTER TABLE [dbo].[Project]
    WITH CHECK ADD CONSTRAINT [FK_Project_Customer] FOREIGN KEY ([CustomerID])
        REFERENCES [dbo].[Customer] ([ID])
GO

ALTER TABLE [dbo].[Project]
    CHECK CONSTRAINT [FK_Project_Customer]
GO


/*****************************************************************************/
/*****                     CREATE TABLE Domain_Project                      **/
/*****************************************************************************/

CREATE TABLE [dbo].[Domain_Project]
(
    [DomainID]      [int] NOT NULL,
    [ProjectID]     [int] NOT NULL,
    [CiresDomainID] [int] NULL,
    CONSTRAINT [PK_Domain_Project] PRIMARY KEY CLUSTERED
        (
         [DomainID] ASC,
         [ProjectID] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[Domain_Project]
    WITH CHECK ADD CONSTRAINT [FK_Teams_Domains] FOREIGN KEY ([DomainID])
        REFERENCES [dbo].[Domains] ([DomainID])
GO

ALTER TABLE [dbo].[Domain_Project]
    CHECK CONSTRAINT [FK_Teams_Domains]
GO

ALTER TABLE [dbo].[Domain_Project]
    WITH CHECK ADD CONSTRAINT [FK_Teams_Project] FOREIGN KEY ([ProjectID])
        REFERENCES [dbo].[Project] ([ID])
GO

ALTER TABLE [dbo].[Domain_Project]
    CHECK CONSTRAINT [FK_Teams_Project]
GO


/*****************************************************************************/
/*****                     CREATE TABLE Unreachable                         **/
/*****************************************************************************/

CREATE TABLE [dbo].[Unreachable]
(
    [ScanID]   [int] NOT NULL,
    [DomainID] [int] NOT NULL,
    [DNSError] [bit] NOT NULL,
    CONSTRAINT [PK_Unreachable] PRIMARY KEY CLUSTERED
        (
         [ScanID] ASC,
         [DomainID] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

/*****************************************************************************/
/*****                     CREATE TABLE CrawlerV10                          **/
/*****************************************************************************/

CREATE TABLE [CrawlerV10]
(
    [ScanID]            [int]            NOT NULL,
    [DomainID]          [int]            NOT NULL,
    [DomainReachable]   [tinyint]        NOT NULL,
    [TestWithSSL]       [bit]            NOT NULL,
    [Redirects]         [smallint]       NULL,
    [StatusCodes]       [nvarchar](50)   NULL,
    [URLs]              [nvarchar](1000) NULL,
    [ScanStatus]        [tinyint]        NOT NULL,
    [LastStatusCode]    [smallint]       NULL,
    [LastURL]           [nvarchar](200)  NULL,
    [IP]                [nvarchar](30)   NULL,
    [RetriesStatuscode] [tinyint]        NULL,
    CONSTRAINT [PK_CrawlerV10] PRIMARY KEY CLUSTERED
        (
         [ScanID] ASC,
         [DomainID] ASC,
         [TestWithSSL] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [CrawlerV10]
    ADD CONSTRAINT [DF_CrawlerV1.0_TestWithSSL] DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [CrawlerV10]
    ADD CONSTRAINT [DF_CrawlerV1.0_Status] DEFAULT ((0)) FOR [ScanStatus]
GO

ALTER TABLE [CrawlerV10]
    WITH CHECK ADD CONSTRAINT [FK_CrawlerV10_Domains] FOREIGN KEY ([DomainID])
        REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [CrawlerV10]
    CHECK CONSTRAINT [FK_CrawlerV10_Domains]
GO

ALTER TABLE [CrawlerV10]
    WITH CHECK ADD CONSTRAINT [FK_CrawlerV10_Scans] FOREIGN KEY ([ScanID])
        REFERENCES [Scans] ([ScanID])
GO

ALTER TABLE [CrawlerV10]
    CHECK CONSTRAINT [FK_CrawlerV10_Scans]
GO


/*****************************************************************************/
/*****                     CREATE TABLE ObservatoryV10                      **/
/*****************************************************************************/

CREATE TABLE [ObservatoryV10]
(
    [ScanID]               [int]           NOT NULL,
    [DomainID]             [int]           NOT NULL,
    [TestWithSSL]          [bit]           NOT NULL,
    [DomainReachable]      [tinyint]       NOT NULL,
    [ScanStatus]           [tinyint]       NOT NULL,
    [Grade]                [nchar](2)      NULL,
    [Score]                [tinyint]       NULL,
    [TestsFailed]          [tinyint]       NULL,
    [TestsPassed]          [tinyint]       NULL,
    [TestsQuantity]        [tinyint]       NULL,
    [CSPPassed]            [bit]           NULL,
    [CSPEval]              [smallint]      NULL,
    [CSPResult]            [nvarchar](100) NULL,
    [CSPDesc]              [nvarchar](250) NULL,
    [CookiesPassed]        [bit]           NULL,
    [CookiesResult]        [nvarchar](100) NULL,
    [CookiesDesc]          [nvarchar](250) NULL,
    [CORSPassed]           [bit]           NULL,
    [CORSResult]           [nvarchar](100) NULL,
    [CORSDesc]             [nvarchar](250) NULL,
    [HPKPPassed]           [bit]           NULL,
    [HPKPResult]           [nvarchar](100) NULL,
    [HPKPDesc]             [nvarchar](250) NULL,
    [RedirectionPassed]    [bit]           NULL,
    [RedirectionResult]    [nvarchar](100) NULL,
    [RedirectionDesc]      [nvarchar](250) NULL,
    [HSTSPassed]           [bit]           NULL,
    [HSTSResult]           [nvarchar](100) NULL,
    [HSTSDesc]             [nvarchar](250) NULL,
    [SRIPassed]            [bit]           NULL,
    [SRIResult]            [nvarchar](100) NULL,
    [SRIDesc]              [nvarchar](250) NULL,
    [XContentTypePassed]   [bit]           NULL,
    [XContentTypeResult]   [nvarchar](100) NULL,
    [XContentTypeDesc]     [nvarchar](250) NULL,
    [XXSSProtectionPassed] [bit]           NULL,
    [XXSSProtectionResult] [nvarchar](100) NULL,
    [XXSSProtectionDesc]   [nvarchar](250) NULL,
    [XFrameOptionsPassed]  [bit]           NULL,
    [XFrameOptionsResult]  [nvarchar](100) NULL,
    [XFrameOptionsDesc]    [nvarchar](250) NULL,
    [ReferrerPolicyPassed] [bit]           NULL,
    [ReferrerPolicyDesc]   [nvarchar](100) NULL,
    [ReferrerPolicyResult] [nvarchar](250) NULL,
    CONSTRAINT [PK_ObservatoryV10] PRIMARY KEY CLUSTERED
        (
         [ScanID] ASC,
         [DomainID] ASC,
         [TestWithSSL] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [ObservatoryV10]
    ADD CONSTRAINT [DF_ObservatoryV10_TestWithSSL] DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [ObservatoryV10]
    WITH CHECK ADD CONSTRAINT [FK_ObservatoryV10_Domains] FOREIGN KEY ([DomainID])
        REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [ObservatoryV10]
    CHECK CONSTRAINT [FK_ObservatoryV10_Domains]
GO

ALTER TABLE [ObservatoryV10]
    WITH CHECK ADD CONSTRAINT [FK_ObservatoryV10_Scans] FOREIGN KEY ([ScanID])
        REFERENCES [Scans] ([ScanID])
GO

ALTER TABLE [ObservatoryV10]
    CHECK CONSTRAINT [FK_ObservatoryV10_Scans]
GO


/*****************************************************************************/
/*****                     CREATE TABLE SecurityHeadersV10                  **/
/*****************************************************************************/

CREATE TABLE [SecurityHeadersV10]
(
    [ScanID]                  [int]           NOT NULL,
    [DomainID]                [int]           NOT NULL,
    [TestWithSSL]             [bit]           NOT NULL,
    [DomainReachable]         [tinyint]       NOT NULL,
    [ScanStatus]              [int]           NOT NULL,
    [Grade]                   [nchar](2)      NULL,
    [XFrameOptions]           [nvarchar](300) NULL,
    [StrictTransportSecurity] [nvarchar](300) NULL,
    [XContentTypeOptions]     [nvarchar](300) NULL,
    [XXSSProtection]          [nvarchar](300) NULL,
    [ContentSecurityPolicy]   [nvarchar](300) NULL,
    [ReferrerPolicy]          [nvarchar](300) NULL,
    [FeaturePolicy]           [nvarchar](300) NULL,
    [ExpectCT]                [nvarchar](300) NULL,
    [ReportTo]                [nvarchar](300) NULL,
    [NEL]                     [nvarchar](300) NULL,
    CONSTRAINT [PK_SecurityHeadersV10] PRIMARY KEY CLUSTERED
        (
         [ScanID] ASC,
         [DomainID] ASC,
         [TestWithSSL] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [SecurityHeadersV10]
    ADD CONSTRAINT [DF_SecurityHeadersV10_TestWithSSL] DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [SecurityHeadersV10]
    WITH CHECK ADD CONSTRAINT [FK_SecurityHeadersV10_Domains] FOREIGN KEY ([DomainID])
        REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [SecurityHeadersV10]
    CHECK CONSTRAINT [FK_SecurityHeadersV10_Domains]
GO

ALTER TABLE [SecurityHeadersV10]
    WITH CHECK ADD CONSTRAINT [FK_SecurityHeadersV10_Scans] FOREIGN KEY ([ScanID])
        REFERENCES [Scans] ([ScanID])
GO

ALTER TABLE [SecurityHeadersV10]
    CHECK CONSTRAINT [FK_SecurityHeadersV10_Scans]
GO


/*****************************************************************************/
/*****                     CREATE TABLE CertificatesV10                     **/
/*****************************************************************************/

CREATE TABLE [CertificatesV10]
(
    [ThumbprintSHA256] [nvarchar](80)  NOT NULL,
    [ThumbprintSHA1]   [nchar](40)     NOT NULL,
    [CommonNames]      nvarchar(MAX)   NULL,
    [AltNames]         nvarchar(MAX)   NULL,
    [SerialNumber]     [nvarchar](100) NULL,
    [Subject]          [nvarchar](300) NULL,
    [IssuerSubject]    [nvarchar](300) NULL,
    [SigAlg]           [nvarchar](30)  NULL,
    [RevocationStatus] [tinyint]       NULL,
    [Issues]           [smallint]      NULL,
    [KeyStrength]      [smallint]      NULL,
    [DebianInsecure]   [bit]           NULL,
    [NextThumbprint]   [nchar](40)     NULL,
    [ValidFrom]        [Datetime]      NULL,
    [ValidTo]          [DateTime]      NULL,
    [CreatedAt]        [Datetime]      NOT NULL,
    [UpdatedAt]        [Datetime]      NOT NULL,
    CONSTRAINT [PK_CertificatesV10] PRIMARY KEY CLUSTERED
        (
         [ThumbprintSHA256] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

/*****************************************************************************/
/*****                     CREATE TABLE CertificateChainsV10                **/
/*****************************************************************************/

CREATE TABLE [CertificateChainsV10]
(
    [ThumbprintSHA256]     [nvarchar](80) NOT NULL,
    [NextThumbprintSHA256] [nvarchar](80) NOT NULL,
    [CreatedAt]            [Datetime]     NULL,
    [UpdatedAt]            [Datetime]     NULL,
    CONSTRAINT [PK_CertificateChainsV10] PRIMARY KEY CLUSTERED
        (
         [ThumbprintSHA256] ASC,
         [NextThumbprintSHA256] ASC
            )
)
GO

ALTER TABLE [CertificateChainsV10]
    WITH CHECK ADD CONSTRAINT [FK_CertificateChainsV10_CertificatesV10_ThumbprintSHA256] FOREIGN KEY ([ThumbprintSHA256])
        REFERENCES [CertificatesV10] ([ThumbprintSHA256])
GO

ALTER TABLE [CertificateChainsV10]
    WITH CHECK ADD CONSTRAINT [FK_CertificateChainsV10_CertificatesV10_NextThumbprintSHA256] FOREIGN KEY ([NextThumbprintSHA256])
        REFERENCES [CertificatesV10] ([ThumbprintSHA256])
GO

/*****************************************************************************/
/*****                     CREATE TABLE SSLLabsV10                          **/
/*****************************************************************************/

CREATE TABLE [SSLLabsV10]
(
    [ScanID]                         [int]            NOT NULL,
    [DomainID]                       [int]            NOT NULL,
    [TestWithSSL]                    [bit]            NOT NULL,
    [DomainReachable]                [tinyint]        NOT NULL,
    [ScanStatus]                     [tinyint]        NOT NULL,
    [IP]                             [nvarchar](30)   NULL,
    [StartTime]                      [DateTime]       NULL,
    [TestTime]                       [DateTime]       NULL,
    [Grade]                          [nvarchar](2)    NULL,
    [GradeTrustIgnored]              [nvarchar](2)    NULL,
    [FutureGrade]                    [nvarchar](2)    NULL,
    [HasWarnings]                    [bit]            NULL,
    [IsExceptional]                  [bit]            NULL,
    [NumberWeakProtocols]            [int]            NULL,
    [WeakProtocols]                  [nvarchar](50)   NULL,
    [NumberProtocols]                [int]            NULL,
    [Protocols]                      [nvarchar](50)   NULL,
    [NumberWeakSuites]               [int]            NULL,
    [WeakSuites]                     [nvarchar](2000) NULL,
    [NumberSuites]                   [int]            NULL,
    [Suites]                         [nvarchar](4000) NULL,
    [ForwardSecrecy]                 [tinyint]        NULL,
    [RenegSupport]                   [tinyint]        NULL,
    [SupportsRC4]                    [bit]            NULL,
    [VulnBeast]                      [bit]            NULL,
    [VulnHeartbleed]                 [bit]            NULL,
    [VulnOpenSslCcs]                 [smallint]       NULL,
    [VulnOpenSSLLuckyMinus20]        [smallint]       NULL,
    [VulnTicketbleed]                [tinyint]        NULL,
    [VulnBleichenbacher]             [smallint]       NULL,
    [VulnPoodle]                     [tinyint]        NULL,
    [VulnFreak]                      [bit]            NULL,
    [VulnLogjam]                     [bit]            NULL,
    [VulnDrown]                      [bit]            NULL,
    [DhUsesKnownPrimes]              [tinyint]        NULL,
    [DhYsReuse]                      [bit]            NULL,
    [EcdhParameterReuse]             [bit]            NULL,
    [CertificateChainIssues]         [smallint]       NULL,
    [CertificateChainLength]         [tinyint]        NULL,
    [EndEntityCertificateThumbprint] [nchar](40)      NULL,
    CONSTRAINT [PK_SSLLabsV10] PRIMARY KEY CLUSTERED
        (
         [ScanID] ASC,
         [DomainID] ASC,
         [TestWithSSL] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [SSLLabsV10]
    ADD CONSTRAINT [DF_SSLLabsV10_TestWithSSL] DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [SSLLabsV10]
    WITH CHECK ADD CONSTRAINT [FK_SSLLabsV10_CertificatesV10] FOREIGN KEY ([EndEntityCertificateThumbprint])
        REFERENCES [CertificatesV10] ([Thumbprint])
GO

ALTER TABLE [SSLLabsV10]
    CHECK CONSTRAINT [FK_SSLLabsV10_CertificatesV10]
GO

ALTER TABLE [SSLLabsV10]
    WITH CHECK ADD CONSTRAINT [FK_SSLLabsV10_Domains] FOREIGN KEY ([DomainID])
        REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [SSLLabsV10]
    CHECK CONSTRAINT [FK_SSLLabsV10_Domains]
GO

ALTER TABLE [SSLLabsV10]
    WITH CHECK ADD CONSTRAINT [FK_SSLLabsV10_Scans] FOREIGN KEY ([ScanID])
        REFERENCES [Scans] ([ScanID])
GO

ALTER TABLE [SSLLabsV10]
    CHECK CONSTRAINT [FK_SSLLabsV10_Scans]
GO

/*****************************************************************************/
/*****                     CREATE TABLE ObservatoryTLSV10                   **/
/*****************************************************************************/

create table ObservatoryTLSV10
(
    ScanID                           int     not null
        constraint ObservatoryTLSV10_Scans_ScanID_fk
            references Scans,
    DomainID                         int     not null
        constraint ObservatoryTLSV10_Domains_DomainID_fk
            references Domains,
    TestWithSSL                      bit default 1,
    DomainReachable                  tinyint not null,
    ScanStatus                       tinyint not null,
    Target                           nvarchar(200),
    ObsScanID                        int,
    EndTime                          datetime,
    MozillaEvaluationWorker_Level    nvarchar(50),
    MozillaGradingWorker_Grade       real,
    MozillaGradingWorker_Lettergrade char,
    Cert_CommonName                  nvarchar(255),
    Cert_AlternativeNames            text,
    Cert_FirstObserved               datetime,
    Cert_ValidFrom                   datetime,
    Cert_ValidTo                     datetime,
    Cert_Key                         nvarchar(100),
    Cert_Issuer                      nvarchar(100),
    Cert_SignatureKeyAlgorithm       nvarchar(100),
    HasCAARecord                     bit,
    ServerSideCipherOrdering         bit,
    OCSPStapling                     bit,
    constraint ObservatoryTLSV10_pk
        primary key nonclustered (ScanID, DomainID, TestWithSSL)
)
go
