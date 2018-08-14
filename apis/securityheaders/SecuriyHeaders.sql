CREATE TABLE [SecurityHeadersV10](
	[ScanID] [int] NOT NULL,
	[DomainID] [int] NOT NULL,
	[TestWithSSL] [bit] NOT NULL,
	[DomainReachable] [tinyint] NOT NULL,
	[ScanStatus] [int] NOT NULL,
	[Grade] [nchar](2) NULL,
	[XFrameOptions] [nvarchar](300) NULL,
	[StrictTransportSecurity] [nvarchar](300) NULL,
	[XContentTypeOptions] [nvarchar](300) NULL,
	[XXSSProtection] [nvarchar](300) NULL,
	[ContentSecurityPolicy] [nvarchar](300) NULL,
	[ReferrerPolicy] [nvarchar](300) NULL,
 CONSTRAINT [PK_SecurityHeadersV10] PRIMARY KEY CLUSTERED 
(
	[ScanID] ASC,
	[DomainID] ASC,
	[TestWithSSL] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [SecurityHeadersV10] ADD  CONSTRAINT [DF_SecurityHeadersV10_TestWithSSL]  DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [SecurityHeadersV10]  WITH CHECK ADD  CONSTRAINT [FK_SecurityHeadersV10_Domains] FOREIGN KEY([DomainID])
REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [SecurityHeadersV10] CHECK CONSTRAINT [FK_SecurityHeadersV10_Domains]
GO

ALTER TABLE [SecurityHeadersV10]  WITH CHECK ADD  CONSTRAINT [FK_SecurityHeadersV10_Scans] FOREIGN KEY([ScanID])
REFERENCES [Scans] ([ScanID])
GO

ALTER TABLE [SecurityHeadersV10] CHECK CONSTRAINT [FK_SecurityHeadersV10_Scans]
GO