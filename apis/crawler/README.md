Redirection-Crawler
============

The redirection crawler follows all the redirects of a domain, while saving
the corresponding domains and their returned status code.
If the status code is >= 500 the crwaler tries 2 more times to get a status
code under 500. If there is a request with a statuscode under 500 the data
will taken. If the webserver send all 3 times a status code >= 500 the data
from the last request will taken.

## Table Columns

| Column |  Description |
| ----------- | ----------- |
| Redirects |  Number of redirects gotten from this site |
| StatusCodes | List of status codes received from each step along the redirect chain |
| URLs | List of all urls received along the redirect chain |
| LastIP | IP of the last host, that was crawled |
| LastStatusCode | Last status code that was returned |
| LastURL | Last crawled URL |
| ScanStatus | Pending: 0, Done: 1, Ignored: 2, Error: 255 |
| RetriesStatuscode | Number of tests if a status code is over/equals 500 (max = 2)|

## Configuration

| Field | Possible Values | Description |
| ----------- | ----------- | ----------- |
| Retries | any positive Integer | Numbers of Errors per Domain until the scan of this domain ultimately fails |
| ScanType | 1-5 | Defines for which Protocol the domain is scanned: 1 only HTTPS; 2 only HTTP; 3 Both; 4 Any but HTTPS is preferred; 5 Any but HTTP is preferred |
| ParallelScans | any positive Integer | Number of scans run simultaneous for this API |
| LogLevel | same as commandline | Sets the verbosity for this API |
| MaxRedirects | any positive Integer | Maximum number of redirects to be followed |
 


