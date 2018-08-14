SecurityHeaders-Scan
============

The SecurityHeaders-Scan performs the scan provided by scotthelme ([securityheaders.com](https://securityheaders.com/))

## Table Columns

| Column |  Description |
| ----------- | ----------- |
| Grade | Received Grade |
| XFrameOptions | XFrameOptions-Header of the domain|
| StrictTransportSecurity | HSTS-Header of the domain|
| XContentTypeOptions| XContentTypeOptions-Header of the domain |
| XXSSProtection | XXSSProtection-Header of the domain |
| ContentSecurityPolicy | CSP-Header of the domain |
| ReferrerPolicy | Referer Policy of the domain |
| ScanStatus | Pending: 0, Done: 1, Ignored: 2, Error: 255 |

 
## Configuration

| Field | Possible Values | Description |
| ----------- | ----------- | ----------- |
| Retries | any positive Integer | Numbers of Errors per Domain until the scan of this domain ultimately fails |
| ScanType | 1-5 | Defines for which Protocol the domain is scanned: 1 only HTTPS; 2 only HTTP; 3 Both; 4 Any but HTTPS is preferred; 5 Any but HTTP is preferred |
| ParallelScans | any positive Integer | Number of scans run simultaneous for this API |
| LogLevel | same as commandline | Sets the verbosity for this API |
| APILocation | URL | Base URL of the API |
| Hidden | "on"/"off" | If "on", results are not published on the website |
| FollowRedirect | "on"/"off" | If "on", the API follows redirects before scanning |