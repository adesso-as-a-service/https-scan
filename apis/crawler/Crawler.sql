CREATE TABLE [CrawlerV10](
	[ScanID] [int] NOT NULL,
	[DomainID] [int] NOT NULL,
	[DomainReachable] [tinyint] NOT NULL,
	[TestWithSSL] [bit] NOT NULL,
	[Redirects] [smallint] NULL,
	[StatusCodes] [nvarchar](50) NULL,
	[URLs] [nvarchar](1000) NULL,
	[ScanStatus] [tinyint] NOT NULL,
	[LastStatusCode] [smallint] NULL,
	[LastURL] [nvarchar](200) NULL,
	[IP] [nvarchar](30) NULL,
 CONSTRAINT [PK_CrawlerV10] PRIMARY KEY CLUSTERED 
(
	[ScanID] ASC,
	[DomainID] ASC,
	[TestWithSSL] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [CrawlerV10] ADD  CONSTRAINT [DF_CrawlerV1.0_TestWithSSL]  DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [CrawlerV10] ADD  CONSTRAINT [DF_CrawlerV1.0_Status]  DEFAULT ((0)) FOR [ScanStatus]
GO

ALTER TABLE [CrawlerV10]  WITH CHECK ADD  CONSTRAINT [FK_CrawlerV10_Domains] FOREIGN KEY([DomainID])
REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [CrawlerV10] CHECK CONSTRAINT [FK_CrawlerV10_Domains]
GO

ALTER TABLE [CrawlerV10]  WITH CHECK ADD  CONSTRAINT [FK_CrawlerV10_Scans] FOREIGN KEY([ScanID])
REFERENCES [Scans] ([ScanID])
GO

ALTER TABLE [CrawlerV10] CHECK CONSTRAINT [FK_CrawlerV10_Scans]
GO