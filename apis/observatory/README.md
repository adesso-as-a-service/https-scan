Observatory-Scan
============

The Observatory-Scan performs the scan provided by mozilla ([observatory.mozilla.org](https://observatory.mozilla.org))

## Table Columns

| Column |  Description |
| ----------- | ----------- |
| Grade |  Grade for the domain |
| Score | Score received for this domain |
| TestsFailed | Number of failed tests |
| TestsPassed | Number of passed tests |
| TestQuantity | Total number of tests |
| CSPPassed | Is true, if CSP has passed the test |
| CSPEval | see [below](#cspeval) |
| CSPResult | Result of the CSP test |
| CSPDesc | Description of the result|
| CookiesPassed | Is true, if cookies have passed the test |
| CookiesResult | Result of the cookie test |
| CookiesDesc | Description of the result|
| CORSPPassed | Is true, if CORS-Policy has passed the test |
| CORSPResult | Result of the CORS-Policy test |
| CORSPDesc | Description of the result|
| HPKPPassed | Is true, if HPKP has passed the test |
| HPKPResult | Result of the HPKP test |
| HPKPDesc | Description of the result|
| RedirectionPassed | Is true, if the redirection test was passed|
| RedirectionResult | Result of the  Redirection test |
| RedirectionDesc | Description of the result|
| HSTSPassed | Is true, if HSTS has passed the test |
| HSTSResult | Result of the HSTS test |
| HSTSDesc | Description of the result|
| SRIPassed | Is true, if SRI test was passed |
| SRIResult | Result of the SRI test |
| SRIDesc | Description of the result|
| XContentTypePassed | Is true, if XContentType test was passed |
| XContentTypeResult | Result of the XContentType test |
| XContentTypeDesc | Description of the result|
| XXSSPassed | Is true, if XXSS test was passed |
| XXSSResult | Result of the XXSS test |
| XXSSDesc | Description of the result|
| XFrameOptionsPassed | Is true, if XFrameOptions test was passed |
| XFrameOptionsResult | Result of the XFrameOptions test |
| XFrameOptionsDesc | Description of the result|
| ScanStatus | Pending: 0, Done: 1, Ignored: 2, Error: 255 |

 
## Details

<a name="cspeval"></a>

### CSPEval
    * 1: No anti-clickjacking
    * 2: No default none
    * 4: Insecure Base-URI
    * 8: Insecure FormAction
    * 16: Insecure Scheme: active
    * 32: Insecure Scheme: passive
    * 64: Strict Dynamic
    * 128: Unsafe Eval
    * 256: Unsafe Inline
    * 512: Unsafe Inline style
    * 1024: Unsafe Objects
