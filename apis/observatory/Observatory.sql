CREATE TABLE [ObservatoryV10](
	[ScanID] [int] NOT NULL,
	[DomainID] [int] NOT NULL,
	[TestWithSSL] [bit] NOT NULL,
	[DomainReachable] [tinyint] NOT NULL,
	[ScanStatus] [tinyint] NOT NULL,
	[Grade] [nchar](2) NULL,
	[Score] [tinyint] NULL,
	[TestsFailed] [tinyint] NULL,
	[TestsPassed] [tinyint] NULL,
	[TestsQuantity] [tinyint] NULL,
	[CSPPassed] [bit] NULL,
	[CSPEval] [smallint] NULL,
	[CSPResult] [nvarchar](100) NULL,
	[CSPDesc] [nvarchar](250) NULL,
	[CookiesPassed] [bit] NULL,
	[CookiesResult] [nvarchar](100) NULL,
	[CookiesDesc] [nvarchar](250) NULL,
	[CORSPassed] [bit] NULL,
	[CORSResult] [nvarchar](100) NULL,
	[CORSDesc] [nvarchar](250) NULL,
	[HPKPPassed] [bit] NULL,
	[HPKPResult] [nvarchar](100) NULL,
	[HPKPDesc] [nvarchar](250) NULL,
	[RedirectionPassed] [bit] NULL,
	[RedirectionResult] [nvarchar](100) NULL,
	[RedirectionDesc] [nvarchar](250) NULL,
	[HSTSPassed] [bit] NULL,
	[HSTSResult] [nvarchar](100) NULL,
	[HSTSDesc] [nvarchar](250) NULL,
	[SRIPassed] [bit] NULL,
	[SRIResult] [nvarchar](100) NULL,
	[SRIDesc] [nvarchar](250) NULL,
	[XContentTypePassed] [bit] NULL,
	[XContentTypeResult] [nvarchar](100) NULL,
	[XContentTypeDesc] [nvarchar](250) NULL,
	[XXSSProtectionPassed] [bit] NULL,
	[XXSSProtectionResult] [nvarchar](100) NULL,
	[XXSSProtectionDesc] [nvarchar](250) NULL,
	[XFrameOptionsPassed] [bit] NULL,
	[XFrameOptionsResult] [nvarchar](100) NULL,
	[XFrameOptionsDesc] [nvarchar](250) NULL,
 CONSTRAINT [PK_ObservatoryV10] PRIMARY KEY CLUSTERED 
(
	[ScanID] ASC,
	[DomainID] ASC,
	[TestWithSSL] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [ObservatoryV10] ADD  CONSTRAINT [DF_ObservatoryV10_TestWithSSL]  DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [ObservatoryV10]  WITH CHECK ADD  CONSTRAINT [FK_ObservatoryV10_Domains] FOREIGN KEY([DomainID])
REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [ObservatoryV10] CHECK CONSTRAINT [FK_ObservatoryV10_Domains]
GO

ALTER TABLE [ObservatoryV10]  WITH CHECK ADD  CONSTRAINT [FK_ObservatoryV10_Scans] FOREIGN KEY([ScanID])
REFERENCES [Scans] ([ScanID])
GO

ALTER TABLE [ObservatoryV10] CHECK CONSTRAINT [FK_ObservatoryV10_Scans]
GO


