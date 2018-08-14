CREATE VIEW [CompleteGrades]
AS
SELECT        ScanID, DomainName, TestWithSSL, SSLLabsStatus, StartTime, SSLLabsGrade, SSLLabsGradeTrustIgnored, SecurityHeadersStatus, SecurityHeadersGrade, ObservatoryStatus, ObservatoryGrade
FROM            CompleteResults
GO