CREATE TABLE [CertificatesV10](
	[Thumbprint] [nchar](40) NOT NULL,
	[ID] [nvarchar](80) NULL,
	[SerialNumber] [nvarchar](100) NULL,
	[Subject] [nvarchar](300) NULL,
	[Issuer] [nvarchar](300) NULL,
	[SigAlg] [nvarchar](30) NULL,
	[RevocationStatus] [tinyint] NULL,
	[Issues] [smallint] NULL,
	[KeyStrength] [smallint] NULL,
	[DebianInsecure] [bit] NULL,
	[NextThumbprint] [nchar](40) NULL,
	[ValidFrom] [Datetime] NULL,
	[ValidTo] [DateTime] NULL,
	[AltNames] nvarchar(MAX) NULL,
 CONSTRAINT [PK_CertificatesV10] PRIMARY KEY CLUSTERED 
(
	[Thumbprint] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [CertificatesV10]  WITH CHECK ADD  CONSTRAINT [FK_CertificatesV10_CertificatesV10] FOREIGN KEY([NextThumbprint])
REFERENCES [CertificatesV10] ([Thumbprint])
GO

ALTER TABLE [CertificatesV10] CHECK CONSTRAINT [FK_CertificatesV10_CertificatesV10]
GO

