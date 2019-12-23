USE [smarthouse_monitoring_https]
GO

/****** Object:  View [dbo].[TestAggregator]    Script Date: 23.12.2019 13:37:30 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO



CREATE VIEW [dbo].[TestAggregator]   
AS
SELECT
	COALESCE(dbo.CrawlerV10.ScanID, dbo.SecurityHeadersV10.ScanID, dbo.SSLLabsV10.ScanID,  dbo.ObservatoryV10.ScanID) AS ScanID,
	COALESCE(dbo.CrawlerV10.DomainID, dbo.SecurityHeadersV10.DomainID, dbo.SSLLabsV10.DomainID, dbo.ObservatoryV10.DomainID) AS DomainID,  
	COALESCE(dbo.CrawlerV10.TestWithSSL, dbo.SecurityHeadersV10.TestWithSSL, dbo.SSLLabsV10.TestWithSSL, dbo.ObservatoryV10.TestWithSSL) AS TestWithSSL, 
	dbo.CrawlerV10.ScanID AS CrawlerScanID,
	dbo.SecurityHeadersV10.ScanID AS SecurityHeadersV10ScanID,
	dbo.SSLLabsV10.ScanID AS SSLLabsV10ScanID,  
	dbo.ObservatoryV10.ScanID AS ObservatoryV10ScanID,
	dbo.SSLLabsV10.ScanStatus AS SSLLabsStatus, 
	dbo.SSLLabsV10.Grade AS SSLLabsGrade, 
	dbo.SSLLabsV10.GradeTrustIgnored AS SSLLabsGradeTrustIgnored, 
	dbo.SecurityHeadersV10.ScanStatus AS SecurityHeadersStatus, 
	dbo.SecurityHeadersV10.Grade AS SecurityHeadersGrade, 
	dbo.ObservatoryV10.ScanStatus AS ObservatoryStatus, 
	dbo.ObservatoryV10.Grade AS ObservatoryGrade, 
	dbo.CrawlerV10.ScanStatus AS CrawlerStatus, 
	dbo.CrawlerV10.Redirects, dbo.CrawlerV10.StatusCodes, 
	dbo.CrawlerV10.URLs, 
	dbo.CrawlerV10.IP AS LastIP, 
	dbo.CrawlerV10.LastStatusCode, 
	dbo.CrawlerV10.LastURL, 
	dbo.SSLLabsV10.IP, 
	dbo.SSLLabsV10.FutureGrade, 
	dbo.SSLLabsV10.HasWarnings, 
	dbo.SSLLabsV10.DomainReachable, 
	dbo.SSLLabsV10.IsExceptional, 
	dbo.SSLLabsV10.WeakProtocols, 
	dbo.SSLLabsV10.NumberWeakProtocols, 
	dbo.SSLLabsV10.NumberProtocols, 
	dbo.SSLLabsV10.Protocols, 
	dbo.SSLLabsV10.NumberWeakSuites, 
	dbo.SSLLabsV10.WeakSuites, 
	dbo.SSLLabsV10.NumberSuites, 
	dbo.SSLLabsV10.ForwardSecrecy, 
	dbo.SSLLabsV10.Suites, 
	dbo.SSLLabsV10.RenegSupport, 
	dbo.SSLLabsV10.VulnBeast, 
	dbo.SSLLabsV10.SupportsRC4, 
	dbo.SSLLabsV10.VulnHeartbleed, 
	dbo.SSLLabsV10.VulnOpenSslCcs, 
	dbo.SSLLabsV10.VulnOpenSSLLuckyMinus20, 
	dbo.SSLLabsV10.VulnTicketbleed, 
	dbo.SSLLabsV10.VulnBleichenbacher, 
	dbo.SSLLabsV10.VulnPoodle, 
	dbo.SSLLabsV10.VulnFreak, 
	dbo.SSLLabsV10.VulnLogjam, 
	dbo.SSLLabsV10.VulnDrown, 
	dbo.SSLLabsV10.DhUsesKnownPrimes, 
	dbo.SSLLabsV10.DhYsReuse, 
	dbo.SSLLabsV10.EcdhParameterReuse, 
	dbo.SSLLabsV10.CertificateChainIssues, 
	dbo.SSLLabsV10.CertificateChainLength, 
	dbo.SSLLabsV10.EndEntityCertificateThumbprint, 
	dbo.SecurityHeadersV10.StrictTransportSecurity, 
	dbo.SecurityHeadersV10.XFrameOptions, 
	dbo.SecurityHeadersV10.XContentTypeOptions, 
	dbo.SecurityHeadersV10.XXSSProtection, 
	dbo.SecurityHeadersV10.ContentSecurityPolicy, 
	dbo.SecurityHeadersV10.ReferrerPolicy, 
	dbo.ObservatoryV10.Score, 
	dbo.ObservatoryV10.TestsFailed, 
	dbo.ObservatoryV10.TestsPassed, 
	dbo.ObservatoryV10.TestsQuantity, 
	dbo.ObservatoryV10.CSPPassed, 
	dbo.ObservatoryV10.CSPEval, 
	dbo.ObservatoryV10.CSPResult, 
	dbo.ObservatoryV10.CSPDesc, 
	dbo.ObservatoryV10.CookiesPassed, 
	dbo.ObservatoryV10.CookiesResult, 
	dbo.ObservatoryV10.CookiesDesc, 
	dbo.ObservatoryV10.CORSPassed, 
	dbo.ObservatoryV10.CORSResult, 
	dbo.ObservatoryV10.CORSDesc, 
	dbo.ObservatoryV10.HPKPPassed, 
	dbo.ObservatoryV10.HPKPResult, 
	dbo.ObservatoryV10.HPKPDesc, 
	dbo.ObservatoryV10.RedirectionPassed, 
	dbo.ObservatoryV10.RedirectionResult, 
	dbo.ObservatoryV10.RedirectionDesc, 
	dbo.ObservatoryV10.HSTSPassed, 
	dbo.ObservatoryV10.HSTSResult, 
	dbo.ObservatoryV10.HSTSDesc, 
	dbo.ObservatoryV10.SRIPassed, 
	dbo.ObservatoryV10.SRIResult, 
	dbo.ObservatoryV10.SRIDesc, 
	dbo.ObservatoryV10.XContentTypePassed, 
	dbo.ObservatoryV10.XContentTypeResult, 
	dbo.ObservatoryV10.XContentTypeDesc, 
	dbo.ObservatoryV10.XXSSProtectionPassed, 
	dbo.ObservatoryV10.XXSSProtectionResult, 
	dbo.ObservatoryV10.XXSSProtectionDesc, 
	dbo.ObservatoryV10.XFrameOptionsPassed, 
	dbo.ObservatoryV10.XFrameOptionsDesc, 
	dbo.ObservatoryV10.XFrameOptionsResult, 
	dbo.ObservatoryV10.ReferrerPolicyPassed, 
	dbo.ObservatoryV10.ReferrerPolicyDesc, 
	dbo.ObservatoryV10.ReferrerPolicyResult
FROM 
	dbo.CrawlerV10 (NOLOCK)
FULL OUTER JOIN
    dbo.SecurityHeadersV10 (NOLOCK)
		ON dbo.SecurityHeadersV10.ScanID = dbo.CrawlerV10.ScanID
		AND dbo.SecurityHeadersV10.DomainID = dbo.CrawlerV10.DomainID 
		AND dbo.SecurityHeadersV10.TestWithSSL = dbo.CrawlerV10.TestWithSSL
FULL OUTER JOIN
	dbo.SSLLabsV10 (NOLOCK)
		ON dbo.SecurityHeadersV10.ScanID = dbo.SSLLabsV10.ScanID 
		AND dbo.SecurityHeadersV10.DomainID = dbo.SSLLabsV10.DomainID 
		AND dbo.SecurityHeadersV10.TestWithSSL = dbo.SSLLabsV10.TestWithSSL 
FULL OUTER JOIN
	dbo.ObservatoryV10 (NOLOCK)
		ON dbo.ObservatoryV10.ScanID = dbo.SecurityHeadersV10.ScanID 
		AND dbo.ObservatoryV10.DomainID = dbo.SecurityHeadersV10.DomainID 
		AND dbo.ObservatoryV10.TestWithSSL = dbo.SecurityHeadersV10.TestWithSSL
GO

EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[35] 4[2] 2[44] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "SecurityHeadersV10"
            Begin Extent = 
               Top = 150
               Left = 644
               Bottom = 280
               Right = 853
            End
            DisplayFlags = 280
            TopColumn = 4
         End
         Begin Table = "SSLLabsV10"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 274
            End
            DisplayFlags = 280
            TopColumn = 36
         End
         Begin Table = "ObservatoryV10"
            Begin Extent = 
               Top = 282
               Left = 636
               Bottom = 397
               Right = 843
            End
            DisplayFlags = 280
            TopColumn = 41
         End
         Begin Table = "CrawlerV10"
            Begin Extent = 
               Top = 5
               Left = 641
               Bottom = 135
               Right = 826
            End
            DisplayFlags = 280
            TopColumn = 7
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 3570
         Alias = 2640
         Table = 2880
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'TestAggregator'
GO

EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'TestAggregator'
GO


