CREATE TABLE [dbo].[Domain_Project](
	[DomainID] [int] NOT NULL,
	[ProjectID] [int] NOT NULL,
	[CiresDomainID] [int] NULL,
 CONSTRAINT [PK_Domain_Project] PRIMARY KEY CLUSTERED 
(
	[DomainID] ASC,
	[ProjectID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [dbo].[Domain_Project]  WITH CHECK ADD  CONSTRAINT [FK_Teams_Domains] FOREIGN KEY([DomainID])
REFERENCES [dbo].[Domains] ([DomainID])
GO

ALTER TABLE [dbo].[Domain_Project] CHECK CONSTRAINT [FK_Teams_Domains]
GO

ALTER TABLE [dbo].[Domain_Project]  WITH CHECK ADD  CONSTRAINT [FK_Teams_Project] FOREIGN KEY([ProjectID])
REFERENCES [dbo].[Project] ([ID])
GO

ALTER TABLE [dbo].[Domain_Project] CHECK CONSTRAINT [FK_Teams_Project]
GO


