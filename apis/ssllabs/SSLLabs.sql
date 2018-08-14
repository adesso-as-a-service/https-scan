CREATE TABLE [SSLLabsV10](
	[ScanID] [int] NOT NULL,
	[DomainID] [int] NOT NULL,
	[TestWithSSL] [bit] NOT NULL,
	[DomainReachable] [tinyint] NOT NULL,
	[ScanStatus] [tinyint] NOT NULL,
	[IP] [nvarchar](30) NULL,
	[StartTime] [bigint] NULL,
	[TestTime] [bigint] NULL,
	[Grade] [nvarchar](2) NULL,
	[GradeTrustIgnored] [nvarchar](2) NULL,
	[FutureGrade] [nvarchar](2) NULL,
	[HasWarnings] [bit] NULL,
	[IsExceptional] [bit] NULL,
	[NumberWeakProtocols] [int] NULL,
	[WeakProtocols] [nvarchar](50) NULL,
	[NumberProtocols] [int] NULL,
	[Protocols] [nvarchar](50) NULL,
	[NumberWeakSuites] [int] NULL,
	[WeakSuites] [nvarchar](2000) NULL,
	[NumberSuites] [int] NULL,
	[Suites] [nvarchar](4000) NULL,
	[ForwardSecrecy] [tinyint] NULL,
	[RenegSupport] [tinyint] NULL,
	[SupportsRC4] [bit] NULL,
	[VulnBeast] [bit] NULL,
	[VulnHeartbleed] [bit] NULL,
	[VulnOpenSslCcs] [smallint] NULL,
	[VulnOpenSSLLuckyMinus20] [smallint] NULL,
	[VulnTicketbleed] [tinyint] NULL,
	[VulnBleichenbacher] [smallint] NULL,
	[VulnPoodle] [tinyint] NULL,
	[VulnFreak] [bit] NULL,
	[VulnLogjam] [bit] NULL,
	[VulnDrown] [bit] NULL,
	[DhUsesKnownPrimes] [tinyint] NULL,
	[DhYsReuse] [bit] NULL,
	[EcdhParameterReuse] [bit] NULL,
	[CertificateChainIssues] [smallint] NULL,
	[CertificateChainLength] [tinyint] NULL,
	[EndEntityCertificateThumbprint] [nchar](40) NULL,
 CONSTRAINT [PK_SSLLabsV10] PRIMARY KEY CLUSTERED 
(
	[ScanID] ASC,
	[DomainID] ASC,
	[TestWithSSL] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [SSLLabsV10] ADD  CONSTRAINT [DF_SSLLabsV10_TestWithSSL]  DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [SSLLabsV10]  WITH CHECK ADD  CONSTRAINT [FK_SSLLabsV10_CertificatesV10] FOREIGN KEY([EndEntityCertificateThumbprint])
REFERENCES [CertificatesV10] ([Thumbprint])
GO

ALTER TABLE [SSLLabsV10] CHECK CONSTRAINT [FK_SSLLabsV10_CertificatesV10]
GO

ALTER TABLE [SSLLabsV10]  WITH CHECK ADD  CONSTRAINT [FK_SSLLabsV10_Domains] FOREIGN KEY([DomainID])
REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [SSLLabsV10] CHECK CONSTRAINT [FK_SSLLabsV10_Domains]
GO

ALTER TABLE [SSLLabsV10]  WITH CHECK ADD  CONSTRAINT [FK_SSLLabsV10_Scans] FOREIGN KEY([ScanID])
REFERENCES [Scans] ([ScanID])
GO

ALTER TABLE [SSLLabsV10] CHECK CONSTRAINT [FK_SSLLabsV10_Scans]
GO


