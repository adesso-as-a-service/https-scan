CREATE VIEW [TestAggregator]
AS
SELECT        SecurityHeadersV10.ScanID, SecurityHeadersV10.DomainID, SecurityHeadersV10.TestWithSSL, SSLLabsV10.ScanStatus AS SSLLabsStatus, SSLLabsV10.Grade AS SSLLabsGrade, 
                         SSLLabsV10.GradeTrustIgnored AS SSLLabsGradeTrustIgnored, SecurityHeadersV10.ScanStatus AS SecurityHeadersStatus, SecurityHeadersV10.Grade AS SecurityHeadersGrade, 
                         ObservatoryV10.ScanStatus AS ObservatoryStatus, ObservatoryV10.Grade AS ObservatoryGrade, CrawlerV10.ScanStatus AS CrawlerStatus, CrawlerV10.Redirects, CrawlerV10.StatusCodes, 
                         CrawlerV10.URLs, CrawlerV10.IP AS LastIP, CrawlerV10.LastStatusCode, CrawlerV10.LastURL, SSLLabsV10.IP, SSLLabsV10.FutureGrade, SSLLabsV10.HasWarnings, 
                         SSLLabsV10.DomainReachable, SSLLabsV10.IsExceptional, SSLLabsV10.WeakProtocols, SSLLabsV10.NumberWeakProtocols, SSLLabsV10.NumberProtocols, SSLLabsV10.Protocols, 
                         SSLLabsV10.NumberWeakSuites, SSLLabsV10.WeakSuites, SSLLabsV10.NumberSuites, SSLLabsV10.ForwardSecrecy, SSLLabsV10.Suites, SSLLabsV10.RenegSupport, SSLLabsV10.VulnBeast, 
                         SSLLabsV10.SupportsRC4, SSLLabsV10.VulnHeartbleed, SSLLabsV10.VulnOpenSslCcs, SSLLabsV10.VulnOpenSSLLuckyMinus20, SSLLabsV10.VulnTicketbleed, SSLLabsV10.VulnBleichenbacher, 
                         SSLLabsV10.VulnPoodle, SSLLabsV10.VulnFreak, SSLLabsV10.VulnLogjam, SSLLabsV10.VulnDrown, SSLLabsV10.DhUsesKnownPrimes, SSLLabsV10.DhYsReuse, 
                         SSLLabsV10.EcdhParameterReuse, SSLLabsV10.CertificateChainIssues, SSLLabsV10.CertificateChainLength, SSLLabsV10.EndEntityCertificateThumbprint, SecurityHeadersV10.StrictTransportSecurity, 
                         SecurityHeadersV10.XFrameOptions, SecurityHeadersV10.XContentTypeOptions, SecurityHeadersV10.XXSSProtection, SecurityHeadersV10.ContentSecurityPolicy, SecurityHeadersV10.ReferrerPolicy, 
                         ObservatoryV10.Score, ObservatoryV10.TestsFailed, ObservatoryV10.TestsPassed, ObservatoryV10.TestsQuantity, ObservatoryV10.CSPPassed, ObservatoryV10.CSPEval, 
                         ObservatoryV10.CSPResult, ObservatoryV10.CSPDesc, ObservatoryV10.CookiesPassed, ObservatoryV10.CookiesResult, ObservatoryV10.CookiesDesc, ObservatoryV10.CORSPassed, 
                         ObservatoryV10.CORSResult, ObservatoryV10.CORSDesc, ObservatoryV10.HPKPPassed, ObservatoryV10.HPKPResult, ObservatoryV10.HPKPDesc, ObservatoryV10.RedirectionPassed, 
                         ObservatoryV10.RedirectionResult, ObservatoryV10.RedirectionDesc, ObservatoryV10.HSTSPassed, ObservatoryV10.HSTSResult, ObservatoryV10.HSTSDesc, ObservatoryV10.SRIPassed, 
                         ObservatoryV10.SRIResult, ObservatoryV10.SRIDesc, ObservatoryV10.XContentTypePassed, ObservatoryV10.XContentTypeResult, ObservatoryV10.XContentTypeDesc, 
                         ObservatoryV10.XXSSProtectionPassed, ObservatoryV10.XXSSProtectionResult, ObservatoryV10.XXSSProtectionDesc, ObservatoryV10.XFrameOptionsPassed, ObservatoryV10.XFrameOptionsDesc, 
                         ObservatoryV10.XFrameOptionsResult
FROM            SecurityHeadersV10 FULL OUTER JOIN
                         SSLLabsV10 ON SSLLabsV10.ScanID = SecurityHeadersV10.ScanID AND SSLLabsV10.DomainID = SecurityHeadersV10.DomainID AND 
                         SSLLabsV10.TestWithSSL = SecurityHeadersV10.TestWithSSL FULL OUTER JOIN
                         ObservatoryV10 ON SecurityHeadersV10.ScanID = ObservatoryV10.ScanID AND SecurityHeadersV10.DomainID = ObservatoryV10.DomainID AND 
                         SecurityHeadersV10.TestWithSSL = ObservatoryV10.TestWithSSL FULL OUTER JOIN
                         CrawlerV10 ON SecurityHeadersV10.ScanID = CrawlerV10.ScanID AND SecurityHeadersV10.DomainID = CrawlerV10.DomainID AND SecurityHeadersV10.TestWithSSL = CrawlerV10.TestWithSSL
GO