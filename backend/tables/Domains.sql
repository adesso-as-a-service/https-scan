CREATE TABLE [dbo].[Domains](
	[DomainID] [int] IDENTITY(1,1) NOT NULL,
	[DomainName] [nvarchar](100) NOT NULL,
	[ListID] [nvarchar](50) NULL,
	[isActive] [bit] NOT NULL,
	[nextScan] [bit] NOT NULL,
	[CreationDate] [datetime2](7) NOT NULL,
	[CustomerID] [int] NULL,
	[DeactivatedDate] [datetime2](7) NULL,
	[Comment] [varchar](100) NULL,
	[isCdn] [bit] NOT NULL,
 CONSTRAINT [PK_Domains] PRIMARY KEY CLUSTERED 
(
	[DomainID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[Domains] ADD  DEFAULT ((1)) FOR [isActive]
GO

ALTER TABLE [dbo].[Domains] ADD  DEFAULT ((0)) FOR [nextScan]
GO

ALTER TABLE [dbo].[Domains] ADD  DEFAULT (sysdatetime()) FOR [CreationDate]
GO

ALTER TABLE [dbo].[Domains] ADD  CONSTRAINT [DF_Domains_isCdn]  DEFAULT ((0)) FOR [isCdn]
GO


