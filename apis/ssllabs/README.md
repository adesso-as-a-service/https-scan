SSLLabs-Scan
============

The SSLLabs-Scan performs the scan provided by Qualys ([ssllabs.com](https://www.ssllabs.com/))

## SSLLabs-Table Columns

| Column |  Description |
| ----------- | ----------- |
| IP                             | IP of the domain |
| StartTime                      | Start time of the scan|
| TestTime                      |  Run time of the scan|
| Grade                          | Grade of the scan |
| GradeTrustIgnored              | Grade, if trust issues were ignored|
| FutureGrade                    | Grade, if upcomming changes are added (unused) |
| HasWarnings                    | Flag, if there are warnings |
| IsExceptional                  | Flag, if site results ar exceptionally good|
| NumberWeakProtocols            | Number of weak used protocols|
| WeakProtocols                  | List of weak protocols|
| NumberProtocols                | Number of protocols|
| Protocols                      | List of weak protocols|
| NumberWeakSuites               | Number of weak cypher suites|
| WeakSuites                     | List of weak cypher suites|
| NumberSuites                   | Number of used cypher suites|
| Suites                         | List of used cypher suites|
| ForwardSecrecy                 | See [below](#fwdsecracy) |
| RenegSupport                   | See [below](#reneg) |
| SupportsRC4                    | Flag, if RC4-Ciphers are supported|
| VulnBeast                     | Flag, if the domain has the Beast vulnerability|
| VulnHeartbleed                 | Flag, if the domain has the heartbleed vulnerability|
| VulnOpenSslCcs                 | See [below](#opensslccs)|
| VulnOpenSSLLuckyMinus20        | See [below](#lucky)|
| VulnTicketbleed                | See [below](#ticketbleed)|
| VulnBleichenbacher             | See [below](#robot)|
| VulnPoodle                     | See [below](#poodle)|
| VulnFreak                      | Flag, if the domain has the Freak vulnerability|
| VulnLogjam                     | Flag, if the domain has the logjam vulnerability|
| VulnDrown                      | Flag, if the domain has the Drown vulnerability|
| DhUsesKnownPrimes              | |
| DhYsReuse                      | |
| EcdhParameterReuse             | |
| CertificateChainIssues         | |
| CertificateChainLength         | |
| EndEntityCertificateThumbprint | |
| StatusCode | Pending: 0, Done: 1, Ignored: 2, Error: 255 |

 ## Certificates-Table Columns

| Column |  Description |
| ----------- | ----------- |
| Grade | Received Grade |
| XFrameOptions | XFrameOptions-Header of the domain|
| StrictTransportSecurity | HSTS-Header of the domain|
| XContentTypeOptions| XContentTypeOptions-Header of the domain |
| XXSSProtection | XXSSProtection-Header of the domain |
| ContentSecurityPolicy | CSP-Header of the domain |
| ReferrerPolicy | Referer Policy of the domain |


## Details



### ForwardSecrecy
<a name="fwdsecracy"></a>
    * bit 0 (1) - set if at least one browser from our simulations negotiated a Forward Secrecy suite.
    * bit 1 (2) - set based on Simulator results if FS is achieved with modern clients. For example, the server supports ECDHE suites, but not DHE.
    * bit 2 (4) - set if all simulated clients achieve FS. In other words, this requires an ECDHE + DHE combination to be supported.

    

### RenegSupport
<a name="reneg"></a>
    * bit 0 (1) - set if insecure client-initiated renegotiation is supported
    * bit 1 (2) - set if secure renegotiation is supported
    * bit 2 (4) - set if secure client-initiated renegotiation is supported
    * bit 3 (8) - set if the server requires secure renegotiation support

### OpenSSLCCS
<a name="opensslccs"></a>
   * -1 - test failed
   * 0 - unknown
   * 1 - not vulnerable
   * 2 - possibly vulnerable, but not exploitable
   * 3 - vulnerable and exploitable

### OpenSSLLuckyMinus20
<a name="lucky"></a>
    * -1 - test failed
    * 0 - unknown
    * 1 - not vulnerable
    * 2 - vulnerable and insecure

### Ticketbleed
<a name="ticketbleed"></a>
   * -1 - test failed
   * 0 - unknown
   * 1 - not vulnerable
   * 2 - vulnerable and insecure

### Bleichenbacher
<a name="robot"></a>
   * -1 - test failed
   * 0 - unknown
   * 1 - not vulnerable
   * 2 - vulnerable (weak oracle)
   * 3 - vulnerable (strong oracle)
   * 4 - inconsistent results

### Poodle
<a name="poodle"></a>
   * -3 - timeout
   * -2 - TLS not supported
   * -1 - test failed
   * 0 - unknown
   * 1 - not vulnerable
   * 2 - vulnerable