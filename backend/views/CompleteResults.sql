CREATE VIEW [CompleteResults]
AS
SELECT        Scans.ScanID, Domains.DomainName, Scans.StartTime, TestAggregator.TestWithSSL, TestAggregator.SSLLabsStatus, TestAggregator.SSLLabsGrade, TestAggregator.SSLLabsGradeTrustIgnored, 
                         TestAggregator.SecurityHeadersStatus, TestAggregator.SecurityHeadersGrade, TestAggregator.ObservatoryStatus, TestAggregator.ObservatoryGrade, TestAggregator.CrawlerStatus, 
                         TestAggregator.Redirects, TestAggregator.StatusCodes, TestAggregator.URLs, TestAggregator.LastIP, TestAggregator.LastStatusCode, TestAggregator.LastURL, TestAggregator.IP, 
                         TestAggregator.FutureGrade, TestAggregator.HasWarnings, TestAggregator.DomainReachable, TestAggregator.IsExceptional, TestAggregator.WeakProtocols, TestAggregator.NumberWeakProtocols, 
                         TestAggregator.NumberProtocols, TestAggregator.Protocols, TestAggregator.NumberWeakSuites, TestAggregator.WeakSuites, TestAggregator.NumberSuites, TestAggregator.ForwardSecrecy, 
                         TestAggregator.Suites, TestAggregator.RenegSupport, TestAggregator.VulnBeast, TestAggregator.SupportsRC4, TestAggregator.VulnHeartbleed, TestAggregator.VulnOpenSslCcs, 
                         TestAggregator.VulnOpenSSLLuckyMinus20, TestAggregator.VulnTicketbleed, TestAggregator.VulnBleichenbacher, TestAggregator.VulnPoodle, TestAggregator.VulnFreak, TestAggregator.VulnLogjam, 
                         TestAggregator.VulnDrown, TestAggregator.DhUsesKnownPrimes, TestAggregator.DhYsReuse, TestAggregator.EcdhParameterReuse, TestAggregator.CertificateChainIssues, 
                         TestAggregator.CertificateChainLength, TestAggregator.EndEntityCertificateThumbprint, TestAggregator.StrictTransportSecurity, TestAggregator.XFrameOptions, TestAggregator.XContentTypeOptions, 
                         TestAggregator.XXSSProtection, TestAggregator.ContentSecurityPolicy, TestAggregator.ReferrerPolicy, TestAggregator.Score, TestAggregator.TestsFailed, TestAggregator.TestsPassed, 
                         TestAggregator.TestsQuantity, TestAggregator.CSPPassed, TestAggregator.CSPEval, TestAggregator.CSPResult, TestAggregator.CSPDesc, TestAggregator.CookiesPassed, 
                         TestAggregator.CookiesResult, TestAggregator.CookiesDesc, TestAggregator.CORSPassed, TestAggregator.CORSResult, TestAggregator.CORSDesc, TestAggregator.HPKPPassed, 
                         TestAggregator.HPKPResult, TestAggregator.HPKPDesc, TestAggregator.RedirectionPassed, TestAggregator.RedirectionResult, TestAggregator.RedirectionDesc, TestAggregator.HSTSPassed, 
                         TestAggregator.HSTSResult, TestAggregator.HSTSDesc, TestAggregator.SRIPassed, TestAggregator.SRIResult, TestAggregator.SRIDesc, TestAggregator.XContentTypePassed, 
                         TestAggregator.XContentTypeResult, TestAggregator.XContentTypeDesc, TestAggregator.XXSSProtectionPassed, TestAggregator.XXSSProtectionResult, TestAggregator.XXSSProtectionDesc, 
                         TestAggregator.XFrameOptionsPassed, TestAggregator.XFrameOptionsDesc, TestAggregator.XFrameOptionsResult
FROM            Scans INNER JOIN
                         TestAggregator ON Scans.ScanID = TestAggregator.ScanID INNER JOIN
                         Domains ON TestAggregator.DomainID = Domains.DomainID
GO
