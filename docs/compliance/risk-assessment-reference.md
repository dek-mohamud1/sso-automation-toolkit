# Risk Assessment Reference: SSO Automation Toolkit

## Risk Categories

### 1. Performance

**Definition:** Impact on application responsiveness, throughput, or resource utilization.

**Project-specific risks:**

- Large or malformed metadata XML files could slow down parsing
- Remote metadata URL fetches are capped at 10s timeout and 5MB to prevent hangs
- Certificate analysis runs synchronously — multiple certs in one file could
  add latency

**Mitigation:** Timeout and size limits already enforced in fetchXmlFromUrl and
multer config. Monitor response times on /api/idp/from-url for slow IdP servers.

---

### 2. Compatibility

**Definition:** Issues with browser support, OS compatibility, or integration
with other systems.

**Project-specific risks:**

- IdP vendors (Azure AD, Okta, ADFS, PingFederate) produce slightly different
  metadata XML structures — namespace variations can break parsing
- Auth0 field name or format changes could make generated packs incorrect
- Node.js version changes could affect crypto.X509Certificate behavior

**Mitigation:** findAllByLocalName() handles namespace-agnostic parsing.
Auth0 output format should be verified after any Auth0 platform updates.

---

### 3. High Complexity

**Definition:** Complex logic that is difficult to understand or maintain.

**Project-specific risks:**

- Recursive XML traversal in findAllByLocalName() is powerful but hard to debug
  when metadata structures are deeply nested or unexpected
- Certificate selection logic (latest expiration) must account for certs with
  missing or unparseable expiration dates
- Attribute mapping uses regex pattern matching which can produce incorrect
  mappings for unusual IdP attribute name formats

**Mitigation:** Fallback logic exists for all three areas. Edge cases should be
regression tested when new IdP formats are encountered.

---

### 4. Tech Debt

**Definition:** Shortcuts or suboptimal code that will need future refactoring.

**Project-specific risks:**

- Prod and UAT domain values are hardcoded in buildServiceProviderPack() —
  should be moved to environment config
- Provider detection relies on simple string matching against entity ID and
  SSO URL — will fail for uncommon or self-hosted IdPs
- No automated tests currently exist for the parsing or generation logic

**Mitigation:** Move hardcoded domains to a config file. Expand provider
detection as new IdP patterns are encountered. Add unit tests for
samlMetadata.js functions.

---

### 5. Dependency

**Definition:** Dependencies on external teams, services, or decisions.

**Project-specific risks:**

- Remote metadata URL fetches depend on the client's IdP being reachable
  from the engineer's network — firewall or VPN restrictions can block fetches
- Auth0 configuration format depends on Florence Healthcare's Auth0 tenant
  setup remaining consistent
- fast-xml-parser npm package — breaking changes in major versions could
  affect parsing behavior

**Mitigation:** File upload is always available as a fallback when URL fetch
fails. Pin npm dependency versions. Test after any Auth0 tenant changes.

---

### 6. Security

**Definition:** Vulnerabilities, access control issues, or sensitive data handling.

**Project-specific risks:**

- Metadata XML URLs could point to internal network resources (SSRF risk) —
  currently only HTTP/HTTPS are allowed but no IP range blocking exists
- Uploaded XML files could contain malicious content beyond SAML metadata
- Certificate and SSO endpoint data is sensitive — must not be logged or persisted
- Tool is internal-only but has no authentication layer — anyone with network
  access to port 5500 could use it

**Mitigation:** Protocol validation exists. Add IP/hostname allowlist for
URL fetching if SSRF becomes a concern. Memory-only storage ensures no
persistence. Consider adding internal auth if tool is ever hosted beyond localhost.

---

### 7. Uncertainty

**Definition:** Missing documentation, unclear requirements, or unknown behavior.

**Project-specific risks:**

- Not all IdP metadata formats are documented — edge cases will surface as
  new clients are onboarded
- Claims and attribute mapping behavior for lesser-known IdPs (e.g. ADFS
  custom configurations) is not fully defined
- No formal spec exists for what the generated SP metadata must contain
  for all supported client IdPs

**Mitigation:** Document new IdP edge cases in this file as they are discovered.
Use the file upload fallback and manual review when URL parsing produces
unexpected results.

---

### 8. Human Error

**Definition:** Potential for mistakes during manual operations.

**Project-specific risks:**

- Engineer could copy the wrong certificate if multiple certs are present —
  tool selects latest automatically but warns when multiple are found
- Engineer could use the UAT pack in a Production Auth0 connection or vice versa
- Incorrect connection identifier when generating SP metadata produces a valid
  but wrong metadata URL that is hard to catch without testing

**Mitigation:** Tool clearly labels Prod vs UAT outputs. Certificate selection
warnings are surfaced explicitly. Engineers should verify the connection
identifier matches the exact Auth0 connection name before generating SP metadata.

---

## Risk Scoring

| Level  | Description                                |
| ------ | ------------------------------------------ |
| Low    | Minor impact, easily mitigated             |
| Medium | Moderate impact, requires attention        |
| High   | Significant impact, needs careful planning |

## Known Risk Summary

| Risk                            | Category      | Level  |
| ------------------------------- | ------------- | ------ |
| Hardcoded Prod/UAT domains      | Tech Debt     | Medium |
| No authentication on server     | Security      | Medium |
| SSRF via metadata URL           | Security      | Medium |
| No automated tests              | Tech Debt     | Medium |
| IdP metadata format variations  | Compatibility | Medium |
| Wrong env pack used in Auth0    | Human Error   | High   |
| Incorrect connection identifier | Human Error   | Medium |
| Remote IdP unreachable          | Dependency    | Low    |
