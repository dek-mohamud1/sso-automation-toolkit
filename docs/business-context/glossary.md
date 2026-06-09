# Glossary: SSO Automation Toolkit

## Domain Terms

| Term                    | Definition                                                                                                            |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Identity Provider (IdP) | The client-side system that authenticates users and issues SAML assertions (e.g. Okta, Azure AD, ADFS, Ping Identity) |
| Service Provider (SP)   | Florence Healthcare's side of the SSO connection — what the client's IdP authenticates users into                     |
| SAML Assertion          | The XML message an IdP sends after a user authenticates, containing user identity and attributes                      |
| Metadata XML            | Standardized XML describing an IdP or SP's SSO configuration — the primary input and output of this tool              |
| Metadata URL            | A direct link to a client's hosted metadata XML file — one of two supported input methods alongside file upload       |
| SSO Connection          | An enterprise connection in Auth0 linking a client's IdP to Florence Healthcare's platform                            |
| Claims                  | User attributes included in a SAML assertion by the IdP (e.g. email, name, employee ID)                               |
| Attribute Mapping       | Matching IdP claim names to the field names Auth0 and Florence Healthcare expect                                      |
| Certificate Expiration  | The date an X.509 certificate becomes invalid — after which all SSO logins will fail                                  |
| Generated Metadata      | The SP metadata XML output produced by the tool for the client to load into their IdP                                 |
| Production (Prod)       | The live client environment — requires its own SSO metadata configuration                                             |
| UAT                     | User Acceptance Testing environment — requires a separate SSO metadata configuration from Prod                        |

## Abbreviations

| Abbreviation | Full Form                          |
| ------------ | ---------------------------------- |
| SSO          | Single Sign-On                     |
| SAML         | Security Assertion Markup Language |
| IdP          | Identity Provider                  |
| SP           | Service Provider                   |
| UAT          | User Acceptance Testing            |
| XML          | Extensible Markup Language         |
| URL          | Uniform Resource Locator           |
| PHI          | Protected Health Information       |
| ACS          | Assertion Consumer Service         |

## Technical Terms

| Term                   | Definition                                                                                                                                          |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| X.509 Certificate      | Signing certificate embedded in SAML metadata — used to verify SAML assertion authenticity. Tool always extracts the latest non-expired certificate |
| Sign-In URL            | IdP endpoint Auth0 redirects users to for authentication — extracted from metadata                                                                  |
| Sign-Out URL           | IdP endpoint used to terminate a user session — extracted from metadata                                                                             |
| Entity ID              | Unique URI identifying the IdP within SAML metadata                                                                                                 |
| ACS URL                | Assertion Consumer Service URL — the Florence Healthcare endpoint the IdP posts SAML responses to after authentication                              |
| Auth0                  | Florence Healthcare's identity platform used to manage all client SSO connections                                                                   |
| Client-side Processing | All parsing and generation runs entirely in the browser — no client data is ever sent to a server                                                   |
