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

-- ALTER TABLE [CertificatesV10]  WITH CHECK ADD  CONSTRAINT [FK_CertificatesV10_CertificatesV10] FOREIGN KEY([NextThumbprint])
-- REFERENCES [CertificatesV10] ([Thumbprint])
-- GO

-- ALTER TABLE [CertificatesV10] CHECK CONSTRAINT [FK_CertificatesV10_CertificatesV10]
-- GO
