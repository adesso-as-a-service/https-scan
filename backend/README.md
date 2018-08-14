SQL-Setup
============

The SQL-Database consists of 8 tables and 5 views. A short explanation to them will be given here.

# Tables

## Scans-Table 

The [Scans-Table](tables/Scans.sql) contains the Meta-Data for all scans. It has the following
columns:

### Table Columns

| Column |  Description |
| ----------- | ----------- |
| ScanID |  The ID is an auto-increment, that specifies a Scan |
| SSLLabs | A boolean, that specifies if SSLLabs was/is used for this scan |
| SSLLabsVersion | The Version number of the table used for the SSLLabs-Results |
| Observatory | A boolean, that specifies if Observatory was/is used for this scan |
| ObservatoryVersion | The Version number of the table used for the Observatory-Results |
| SecurityHeaders | A boolean, that specifies if SecurityHeaders was/is used for this scan |
| SecurityHeadersVersion | The Version number of the table used for the SecurityHeaders-Results |
| Crawler | A boolean, that specifies if Crawler was/is used for this scan |
| CrawlerVersion | The Version number of the table used for the Crawler-Results |
| Unreachable | Number of hosts, that were not reachable |
| Total | Total number of hosts |
| Done | Boolean, implicating if the scan is finished |
| StartTime | Timestamp (Server Time) when the Scan was started |
| Config | The used API-Configurations in json-Format |

## Domains-Table 

The [Domains-Table](tables/Domains.sql) contains all Domains that were scanned and is used to sort 
them in different lists. It has the following columns:

### Table Columns

| Column |  Description |
| ----------- | ----------- |
| DomainID |  The ID is an auto-increment, that specifies a Domain |
| DomainName | The host/domain name |
| ListID | An identifier to specify to which List a Domain belongs |
| isActive | A boolean, that specifies if a domain is active. Inactive domains are not scanned |
| nextScan | A boolean, that specifies if a domain is going to be in the next scan |
| CreationDate | A timestamp (Server Time) of the point in time the domain was added to the table |


## Unreachable-Table 

The [Unreachable-Table](tables/Unreachable.sql) contains all Domains that were unreachable during a scan.
 It has the following columns:

 ### Table Columns

| Column |  Description |
| ----------- | ----------- |
| ScanID |  ID specifying the scan |
| DomainID | ID specifying the Domain |
| DNSError | A boolean, that specifies if the domain was unreachable due to a DNS-Lookup error (No such host!) |

## API-Tables

| Table | Description |
| ----------- | ----------- |
| [Crawler-Table](/apis/crawler/Crawler.sql) | [Description](/apis/crawler/README.md) |
| [Observatory-Table](/apis/observatory/Observatory.sql) | [Description](/apis/observatory/README.md) |
| [SecurityHeaders-Table](/apis/observatory/Observatory.sql) | [Description](/apis/observatory/README.md) |
| [SSLLabs-Table](/apis/ssllabs/SSLLabs.sql) | [Description](/apis/ssllabs/README.md) |
| [Certificates-Table](/apis/ssllabs/Certificates.sql) | [Description](/apis/ssllabs/README.md) |

# Views

## TestAggregation-View

This [view](views/TestAggregation.sql) combines the results from all APIs  per Scan and Domain.

## CompleteResults-View

This [view](views/CompleteResults.sql) just adds the DomainName to each entry in the TestAggregation-View.

## CompleteGrades-View

This [view](views/CompleteGrades.sql) just shows the Grades of each Test for each entry in the CompleteResults-View.

## LatestResults-View

This [view](views/LatestResults.sql) just shows the entries of the CompleteResults-View for the newest Scan.

## LatestGrades-View

This [view](views/LatestGrades.sql) just shows the entries of the CompleteGrades-View for the newest Scan.