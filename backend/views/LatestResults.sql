CREATE VIEW [LatestResults]
AS
SELECT        DomainName, StartTime, TestWithSSL, SSLLabsStatus, SSLLabsGrade, SSLLabsGradeTrustIgnored, SecurityHeadersStatus, SecurityHeadersGrade, ObservatoryStatus, ObservatoryGrade, CrawlerStatus, Redirects, 
                         StatusCodes, URLs, LastIP, LastStatusCode, LastURL, IP, FutureGrade, HasWarnings, DomainReachable, IsExceptional, WeakProtocols, NumberWeakProtocols, NumberProtocols, Protocols, NumberWeakSuites, WeakSuites, 
                         NumberSuites, ForwardSecrecy, Suites, RenegSupport, VulnBeast, SupportsRC4, VulnHeartbleed, VulnOpenSslCcs, VulnOpenSSLLuckyMinus20, VulnTicketbleed, VulnBleichenbacher, VulnPoodle, VulnFreak, VulnLogjam, 
                         VulnDrown, DhUsesKnownPrimes, DhYsReuse, EcdhParameterReuse, CertificateChainIssues, CertificateChainLength, EndEntityCertificateThumbprint, StrictTransportSecurity, XFrameOptions, XContentTypeOptions, 
                         XXSSProtection, ContentSecurityPolicy, ReferrerPolicy, Score, TestsFailed, TestsPassed, TestsQuantity, CSPPassed, CSPEval, CSPResult, CSPDesc, CookiesPassed, CookiesResult, CookiesDesc, CORSPassed, CORSResult, 
                         CORSDesc, HPKPPassed, HPKPResult, HPKPDesc, RedirectionPassed, RedirectionResult, RedirectionDesc, HSTSPassed, HSTSResult, HSTSDesc, SRIPassed, SRIResult, SRIDesc, XContentTypePassed, XContentTypeResult, 
                         XContentTypeDesc, XXSSProtectionPassed, XXSSProtectionResult, XXSSProtectionDesc, XFrameOptionsPassed, XFrameOptionsDesc, XFrameOptionsResult
FROM            CompleteResults
WHERE        (ScanID = IDENT_CURRENT('Scans'))
GO