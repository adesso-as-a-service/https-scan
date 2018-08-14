CREATE VIEW [LatestGrades]
AS
SELECT        DomainName, TestWithSSL, SSLLabsStatus, StartTime, SSLLabsGrade, SSLLabsGradeTrustIgnored, SecurityHeadersStatus, SecurityHeadersGrade, ObservatoryStatus, ObservatoryGrade
FROM            CompleteGrades
WHERE        (ScanID = IDENT_CURRENT('Scans'))
GO