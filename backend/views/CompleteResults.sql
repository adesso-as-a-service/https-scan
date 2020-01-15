USE [smarthouse_monitoring_https]
GO

/****** Object:  View [dbo].[NewCompleteResult]    Script Date: 23.12.2019 13:29:46 ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO




CREATE VIEW [dbo].[CompleteResult]
AS
SELECT 
	dbo.Scans.ScanID, 
	dbo.Domains.DomainID, 
	dbo.Domains.DomainName, 
	dbo.Project.ID AS ProjectID, 
	dbo.Project.Name AS ProjectName, 
	dbo.Customer.ID AS CustomerID, 
	dbo.Customer.Name AS CustomerName, 
	dbo.Scans.StartTime, 
	dbo.TestAggregator.TestWithSSL, 
	dbo.TestAggregator.DomainReachable, 
	dbo.TestAggregator.SSLLabsStatus, 
	dbo.TestAggregator.SSLLabsGrade, 
	dbo.TestAggregator.SSLLabsGradeTrustIgnored, 
	dbo.TestAggregator.SecurityHeadersStatus, 
	dbo.TestAggregator.ObservatoryStatus, 
	dbo.TestAggregator.SecurityHeadersGrade, 
	dbo.TestAggregator.ObservatoryGrade, 
	dbo.TestAggregator.CrawlerStatus, 
	dbo.TestAggregator.Redirects, 
	dbo.TestAggregator.StatusCodes, 
	dbo.TestAggregator.URLs, 
	dbo.TestAggregator.LastIP, 
	dbo.TestAggregator.LastStatusCode, 
	dbo.TestAggregator.LastURL, 
	dbo.TestAggregator.IP, 
	dbo.TestAggregator.FutureGrade, 
	dbo.TestAggregator.HasWarnings, 
	dbo.TestAggregator.IsExceptional, 
	dbo.TestAggregator.WeakProtocols, 
	dbo.TestAggregator.NumberWeakProtocols, 
	dbo.TestAggregator.NumberProtocols, 
	dbo.TestAggregator.Protocols, 
	dbo.TestAggregator.NumberWeakSuites, 
	dbo.TestAggregator.WeakSuites, 
	dbo.TestAggregator.NumberSuites, 
	dbo.TestAggregator.ForwardSecrecy, 
	dbo.TestAggregator.Suites, 
	dbo.TestAggregator.RenegSupport, 
	dbo.TestAggregator.VulnBeast, 
	dbo.TestAggregator.SupportsRC4, 
	dbo.TestAggregator.VulnHeartbleed, 
	dbo.TestAggregator.VulnOpenSslCcs, 
	dbo.TestAggregator.VulnOpenSSLLuckyMinus20, 
	dbo.TestAggregator.VulnTicketbleed, 
	dbo.TestAggregator.VulnBleichenbacher, 
	dbo.TestAggregator.VulnPoodle, 
	dbo.TestAggregator.VulnFreak, 
	dbo.TestAggregator.VulnLogjam, 
	dbo.TestAggregator.VulnDrown, 
	dbo.TestAggregator.DhUsesKnownPrimes, 
	dbo.TestAggregator.DhYsReuse, 
	dbo.TestAggregator.EcdhParameterReuse, 
	dbo.TestAggregator.CertificateChainIssues, 
	dbo.TestAggregator.CertificateChainLength, 
	dbo.TestAggregator.EndEntityCertificateThumbprint, 
	dbo.TestAggregator.StrictTransportSecurity, 
	dbo.TestAggregator.XFrameOptions, 
	dbo.TestAggregator.XContentTypeOptions, 
	dbo.TestAggregator.XXSSProtection, 
	dbo.TestAggregator.ContentSecurityPolicy, 
	dbo.TestAggregator.ReferrerPolicy, 
	dbo.TestAggregator.Score, 
	dbo.TestAggregator.TestsFailed, 
	dbo.TestAggregator.TestsPassed, 
	dbo.TestAggregator.TestsQuantity, 
	dbo.TestAggregator.CSPPassed, 
	dbo.TestAggregator.CSPEval, 
	dbo.TestAggregator.CSPResult, 
	dbo.TestAggregator.CSPDesc, 
	dbo.TestAggregator.CookiesPassed, 
	dbo.TestAggregator.CookiesResult, 
	dbo.TestAggregator.CookiesDesc, 
	dbo.TestAggregator.CORSPassed, 
	dbo.TestAggregator.CORSResult, 
	dbo.TestAggregator.CORSDesc, 
	dbo.TestAggregator.HPKPPassed, 
	dbo.TestAggregator.HPKPResult, 
	dbo.TestAggregator.HPKPDesc, 
	dbo.TestAggregator.RedirectionPassed, 
	dbo.TestAggregator.RedirectionResult, 
	dbo.TestAggregator.RedirectionDesc, 
	dbo.TestAggregator.HSTSPassed, 
	dbo.TestAggregator.HSTSResult, 
	dbo.TestAggregator.HSTSDesc, 
	dbo.TestAggregator.SRIPassed, 
	dbo.TestAggregator.SRIResult, 
	dbo.TestAggregator.SRIDesc, 
	dbo.TestAggregator.XContentTypePassed, 
	dbo.TestAggregator.XContentTypeResult, 
	dbo.TestAggregator.XContentTypeDesc, 
	dbo.TestAggregator.XXSSProtectionPassed, 
	dbo.TestAggregator.XXSSProtectionResult, 
	dbo.TestAggregator.XXSSProtectionDesc, 
	dbo.TestAggregator.XFrameOptionsPassed, 
	dbo.TestAggregator.XFrameOptionsDesc, 
	dbo.TestAggregator.XFrameOptionsResult, 
	dbo.TestAggregator.ReferrerPolicyPassed, 
	dbo.TestAggregator.ReferrerPolicyResult, 
	dbo.TestAggregator.ReferrerPolicyDesc, 
	dbo.TestAggregator.FeaturePolicy, 
	dbo.TestAggregator.ExpectCT, 
	dbo.TestAggregator.ReportTo,
	dbo.TestAggregator.NEL, 
	dbo.CertificatesV10.SerialNumber AS CertificateSerialNumber, 
	dbo.CertificatesV10.Subject AS CertificateSubject, 
	dbo.CertificatesV10.Issuer AS CertificateIssuer, 
	dbo.CertificatesV10.SigAlg AS CertificateSigAlg, 
	dbo.CertificatesV10.RevocationStatus AS CertificateRevocationStatus, 
	dbo.CertificatesV10.KeyStrength AS CertificateKeyStrength, 
	dbo.CertificatesV10.Issues AS CertificateIssues, 
	dbo.CertificatesV10.DebianInsecure AS CertificateDebianInsecure, 
	dbo.CertificatesV10.NextThumbprint AS CertificateNextThumbprint, 
	dbo.CertificatesV10.ValidFrom AS CertificateValidFrom, 
	dbo.CertificatesV10.ValidTo AS CertificateValidTo, 
	dbo.CertificatesV10.AltNames AS CertificateAltNames
FROM
	dbo.Scans (NOLOCK)
LEFT JOIN 
	dbo.TestAggregator (NOLOCK)
		ON dbo.TestAggregator.ScanID = dbo.Scans.ScanID 
LEFT JOIN 
	dbo.CertificatesV10 (NOLOCK)
		ON dbo.TestAggregator.EndEntityCertificateThumbprint = dbo.CertificatesV10.Thumbprint 
LEFT JOIN 
	dbo.Domains (NOLOCK)
		ON dbo.TestAggregator.DomainID = dbo.Domains.DomainID 
LEFT JOIN 
	dbo.Customer (NOLOCK)
		ON dbo.Domains.CustomerID = dbo.Customer.ID 
LEFT JOIN
	dbo.Domain_Project (NOLOCK)
		ON dbo.Domain_Project.DomainID = dbo.Domains.DomainID
LEFT JOIN 
	dbo.Project (NOLOCK)
		ON dbo.Project.ID = dbo.Domain_Project.ProjectID 
GO

EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
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
         Begin Table = "Project"
            Begin Extent = 
               Top = 26
               Left = 1161
               Bottom = 156
               Right = 1328
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Domain_Project"
            Begin Extent = 
               Top = 9
               Left = 921
               Bottom = 122
               Right = 1089
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "TestAggregator"
            Begin Extent = 
               Top = 9
               Left = 375
               Bottom = 139
               Right = 632
            End
            DisplayFlags = 280
            TopColumn = 1
         End
         Begin Table = "Scans"
            Begin Extent = 
               Top = 10
               Left = 26
               Bottom = 140
               Right = 239
            End
            DisplayFlags = 280
            TopColumn = 10
         End
         Begin Table = "Domains"
            Begin Extent = 
               Top = 9
               Left = 707
               Bottom = 139
               Right = 882
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Customer"
            Begin Extent = 
               Top = 129
               Left = 919
               Bottom = 225
               Right = 1086
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "CertificatesV10"
            Begin Extent = 
               Top = 148
               Left = 25
               Bottom = 278
               Right = 205
            End
        ' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'NewCompleteResult'
GO

EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'    DisplayFlags = 280
            TopColumn = 0
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
         Column = 1440
         Alias = 2595
         Table = 1170
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
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'NewCompleteResult'
GO

EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'NewCompleteResult'
GO


