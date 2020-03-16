create table ObservatoryTLSV10
(
    ScanID                           int     not null
        constraint ObservatoryTLSV10_Scans_ScanID_fk
            references Scans,
    DomainID                         int     not null
        constraint ObservatoryTLSV10_Domains_DomainID_fk
            references Domains,
    TestWithSSL                      bit default 1,
    DomainReachable                  tinyint not null,
    ScanStatus                       tinyint not null,
    Target                           nvarchar(200),
    ObsScanID                        int,
    EndTime                          datetime,
    MozillaEvaluationWorker_Level    nvarchar(50),
    MozillaGradingWorker_Grade       real,
    MozillaGradingWorker_Lettergrade char,
    Cert_CommonName                  nvarchar(255),
    Cert_AlternativeNames            text,
    Cert_FirstObserved               datetime,
    Cert_ValidFrom                   datetime,
    Cert_ValidTo                     datetime,
    Cert_Key                         nvarchar(100),
    Cert_Issuer                      nvarchar(100),
    Cert_SignatureKeyAlgorithm       nvarchar(100),
    HasCAARecord                     bit,
    ServerSideCipherOrdering         bit,
--	SupportedClients text,
--	UnsupportedClients text,
    OCSPStapling                     bit,
    constraint ObservatoryTLSV10_pk
        primary key nonclustered (ScanID, DomainID, TestWithSSL)
)
go

