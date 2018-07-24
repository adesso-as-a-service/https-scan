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
| DhUsesKnownPrimes              | See [below](#known) |
| DhYsReuse                      |  true if the DH ephemeral server value is reused. Not present if the server doesn't support the DH key exchange |
| EcdhParameterReuse             |true if the server reuses its ECDHE values |
| CertificateChainIssues         | See [below](#chain) |
| CertificateChainLength         | Length of the Certificate Chain |
| EndEntityCertificateThumbprint | Thumbprint of the EndEntity Certificate|
| StatusCode | Pending: 0, Done: 1, Ignored: 2, Error: 255 |

 ## Certificates-Table Columns

| Column |  Description |
| ----------- | ----------- |
| Thumbprint       | Certificate Thumbprint |
| ID               |  Certificate ID |
| SerialNumber     | Certificate Serialnumber |
| Subject          | Subject |
| Issuer           | Issuer |
| SigAlg           | Signature Algorithm |
| RevocationStatus | See [below](#revoc) |
| Issues           | See [below](#CertIssue) |
| KeyStrength      | Keystrength |
| DebianInsecure   | true if debian flaw is found |
| NotBefore        | Not valid before  |
| NotAfter         |  Not valid after|
| NextThumbprint |  Thumbprint of the signing certificate |


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

### Poodle
<a name="known"></a>
  * 0 - no
  * 1 - yes, but they're not weak
  * 2 - yes and they're weak

### Certificate Chain Issues
<a name="known"></a>
   * bit 0 (1) - unused
   * bit 1 (2) - incomplete chain (set only when we were able to build a chain by adding missing intermediate certificates from external sources)
   * bit 2 (4) - chain contains unrelated or duplicate certificates (i.e., certificates that are not part of the same chain)
   * bit 3 (8) - the certificates form a chain (trusted or not), but the order is incorrect
   * bit 4 (16) - contains a self-signed root certificate (not set for self-signed leafs)
   * bit 5 (32) - the certificates form a chain (if we added external certificates, bit 1 will be set), but we could not validate it. If the leaf was trusted, that means that we built a different chain we trusted.

### Certificate Revocation Status
<a name="revoc"></a>
   * 0 - not checked
   * 1 - certificate revoked
   * 2 - certificate not revoked
   * 3 - revocation check error
   * 4 - no revocation information
   * 5 - internal error

### Certificate Issues
<a name="CertIssue"></a>
   * bit 0 (1) - no chain of trust
   * bit 1 (2) - not before
   * bit 2 (4) - not after
   * bit 3 (8) - hostname mismatch
   * bit 4 (16) - revoked
   * bit 5 (32) - bad common name
   * bit 6 (64) - self-signed
   * bit 7 (128) - blacklisted
   * bit 8 (256) - insecure signature
   * bit 9 (512) - insecure key