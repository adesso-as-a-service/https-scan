CREATE TABLE [dbo].[Scans](
	[ScanID] [int] IDENTITY(1,1) NOT NULL,
	[SSLLabs] [bit] NOT NULL,
	[SSLLabsVersion] [nvarchar](4) NULL,
	[Observatory] [bit] NOT NULL,
	[ObservatoryVersion] [nvarchar](4) NULL,
	[SecurityHeaders] [bit] NOT NULL,
	[SecurityHeadersVersion] [nvarchar](4) NULL,
	[Crawler] [bit] NOT NULL,
	[CrawlerVersion] [nvarchar](4) NULL,
	[Unreachable] [int] NULL,
	[Total] [int] NULL,
	[Done] [bit] NOT NULL,
	[StartTime] [datetime2](2) NOT NULL,
	[Config] [nvarchar](2000) NULL,
 CONSTRAINT [PK_Scans] PRIMARY KEY CLUSTERED 
(
	[ScanID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[Scans] ADD  CONSTRAINT [DF_Scans_StartTime]  DEFAULT (getdate()) FOR [StartTime]
GO


