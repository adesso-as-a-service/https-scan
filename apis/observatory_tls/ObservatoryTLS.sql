-- Create ObservatoryTLS table
CREATE TABLE [ObservatoryTLSV10]
(
    [ScanID]                       [int]           NOT NULL,
    [DomainID]                     [int]           NOT NULL,
    [TestWithSSL]                  [bit]           NOT NULL,

    -- These two seem to be required by the scanner
    [DomainReachable]              [tinyint]       NOT NULL,
    [ScanStatus]                   [tinyint]       NOT NULL,

    [ObservatoryTLSScanId]         [int]           NULL,

    [Timestamp]                    [datetime]      NULL,
    [Target]                       [nvarchar](200) NULL,
    [Replay]                       [int]           NULL,
    [HasTLS]                       [bit]           NULL,
    [ObservatoryCertID]            [int]           NULL,
    [ObservatoryTrustID]           [int]           NULL,
    [IsValid]                      [bit]           NULL,

    [ConnectionInfoScanIP]         [nvarchar](15)  NULL,
    [ConnectionInfoServerside]     [bit]           NULL,
    [ConnectionInfoCurvesFallback] [bit]           NULL,
    CONSTRAINT [PK_ObservatoryTLSV10] PRIMARY KEY CLUSTERED
        (
         [ScanID] ASC,
         [DomainID] ASC,
         [TestWithSSL] ASC
            ) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, FILLFACTOR = 80) ON [PRIMARY]
) ON [PRIMARY]
GO

ALTER TABLE [ObservatoryTLSV10]
    ADD CONSTRAINT [DF_ObservatoryTLSV10_TestWithSSL] DEFAULT ((0)) FOR [TestWithSSL]
GO

ALTER TABLE [ObservatoryTLSV10]
    WITH CHECK ADD CONSTRAINT [FK_ObservatoryTLSV10_Domains] FOREIGN KEY ([DomainID])
        REFERENCES [Domains] ([DomainID])
GO

ALTER TABLE [ObservatoryTLSV10]
    CHECK CONSTRAINT [FK_ObservatoryTLSV10_Domains]
GO

ALTER TABLE [ObservatoryTLSV10]
    WITH CHECK ADD CONSTRAINT [FK_ObservatoryTLSV10_Scans] FOREIGN KEY ([ScanID])
        REFERENCES [Scans] ([ScanID])
GO
