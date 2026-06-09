# System Overview: SSO Automation Toolkit

## Architecture

A Node.js/Express web application with a lightweight backend server and a
static frontend. The backend handles all SAML metadata fetching, XML parsing,
certificate analysis, and configuration pack generation. The frontend sends
requests to the backend API and renders the results for the engineer.

## Components

### Frontend

- **Technology:** Vanilla JavaScript, HTML, CSS (static files in /public)
- **Description:** Single-page interface that accepts metadata input (URL or
  file upload), sends it to the backend API, and renders extracted SSO values,
  certificate expiration dates, claims/attributes, and generated output metadata
  for both Prod and UAT.

### Backend

- **Technology:** Node.js, Express (server.js)
- **Description:** Express server running on port 5500. Handles three API routes:
  parsing metadata from a URL, parsing metadata from a file upload, and generating
  SP metadata packs. Applies input validation, security headers, file size limits,
  and memory-only file storage via multer. No data is ever written to disk.

### SAML Metadata Module

- **Technology:** Node.js module (samlMetadata.js), fast-xml-parser, Node crypto
- **Description:** Core logic layer. Handles XML fetching, namespace-agnostic
  parsing, certificate extraction and analysis, service endpoint selection,
  IdP provider detection (Azure AD, Okta, Google, PingFederate, OneLogin),
  Auth0 attribute mapping, and SP metadata pack generation.

### Database

- **Technology:** N/A
- **Description:** No database. All processing is in-memory only. Data is
  discarded at the end of each request.

### Infrastructure

- **Technology:** Local Node.js server
- **Description:** Runs locally via Node.js. No cloud deployment, no build
  pipeline, no external dependencies beyond npm packages.

## Integration Points

| Service                 | Purpose                                                                                    | Protocol                 |
| ----------------------- | ------------------------------------------------------------------------------------------ | ------------------------ |
| Client IdP Metadata URL | Fetch client-provided SAML metadata XML                                                    | HTTPS GET                |
| Auth0                   | Target platform where extracted values are entered to configure enterprise SSO connections | Manual input by engineer |

## API Routes

| Method | Route              | Purpose                                          |
| ------ | ------------------ | ------------------------------------------------ |
| POST   | /api/idp/from-url  | Parse IdP metadata from a remote URL             |
| POST   | /api/idp/from-file | Parse IdP metadata from an uploaded XML file     |
| POST   | /api/sp/generate   | Generate SP metadata pack for Prod, UAT, or both |
| GET    | /api/health        | Health check                                     |

## Data Flow

1. Engineer provides metadata input — a direct XML URL or a file upload
2. Backend fetches or reads the XML (10s timeout, 5MB max for URLs, 2MB for files)
3. samlMetadata.js parses the XML and extracts:
   - Sign-In URL, Sign-Out URL, Entity ID
   - Latest X.509 certificate + expiration date
   - Claims and attributes
   - Detected IdP provider
4. Auth0 configuration pack is built with extracted values and attribute mappings
5. Engineer uses the pack to configure the Auth0 enterprise SSO connection
6. Engineer requests SP metadata generation for Prod, UAT, or both
7. Tool generates ACS URL, Entity ID, and metadata URL per environment
8. Engineer downloads or copies the output and hands it off to the client's IdP
9. No data is persisted at any point — everything is request-scoped only

## Security

- Memory-only file storage via multer — no files written to disk
- Input validation on all routes (URL format, identifier format, environment)
- File upload restricted to XML only, 2MB max
- Security headers applied globally (X-Content-Type-Options, X-Frame-Options,
  X-XSS-Protection, Referrer-Policy)
- No data persistence across requests
