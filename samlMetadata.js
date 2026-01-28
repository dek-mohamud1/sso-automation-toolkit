/* =========================================================
   SSO Automation Toolkit — SAML Metadata Parser
   Author: Dek Mohamud
   Description:
   Parse SAML metadata XML, extract certificates, endpoints,
   and generate configuration packs for Auth0 and Service
   Provider setups.
   
   Security: Input validation, error handling, no persistence
   ========================================================= */

import { XMLParser } from "fast-xml-parser";
import crypto from "crypto";

// ==================== CONSTANTS ====================
const FETCH_TIMEOUT = 10000; // 10 seconds
const MAX_XML_SIZE = 5 * 1024 * 1024; // 5MB
const MAX_URL_LENGTH = 2048;

// ==================== XML FETCHING ====================

/**
 * Fetches XML from a remote URL with validation and timeout
 * @param {string} url - Metadata URL to fetch
 * @returns {Promise<string>} XML content
 * @throws {Error} If URL is invalid or fetch fails
 */
export async function fetchXmlFromUrl(url) {
  // Validate URL
  if (!url || typeof url !== "string") {
    throw new Error("URL is required");
  }

  if (url.length > MAX_URL_LENGTH) {
    throw new Error("URL exceeds maximum length");
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error("Invalid URL format");
  }

  // Only allow HTTP/HTTPS protocols
  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    throw new Error("Only HTTP and HTTPS protocols are allowed");
  }

  try {
    // Fetch with timeout using AbortController
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

    const response = await fetch(parsedUrl.toString(), {
      method: "GET",
      headers: {
        Accept: "application/xml,text/xml,*/*",
        "User-Agent": "SSO-Toolkit/1.0",
      },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    // Handle HTTP errors
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error(
          "Metadata not found (HTTP 404). Verify the URL and connection name are correct.",
        );
      }
      if (response.status === 403) {
        throw new Error(
          "Access forbidden (HTTP 403). The metadata may require authentication.",
        );
      }
      throw new Error(`Failed to fetch metadata (HTTP ${response.status})`);
    }

    const text = await response.text();

    // Validate response
    if (!text || typeof text !== "string") {
      throw new Error("Empty response from server");
    }

    if (text.length > MAX_XML_SIZE) {
      throw new Error(
        `Response too large (max ${MAX_XML_SIZE / 1024 / 1024}MB)`,
      );
    }

    if (!text.includes("<")) {
      throw new Error("Response does not appear to be XML");
    }

    return text;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error(
        "Request timed out. The server may be slow or unreachable.",
      );
    }
    throw err;
  }
}

// ==================== XML PARSING ====================

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  allowBooleanAttributes: true,
  parseTagValue: true,
  trimValues: true,
  stopNodes: ["*.X509Certificate"], // Preserve certificate whitespace
});

/**
 * Parses SAML metadata XML into structured data
 * @param {string} xml - SAML metadata XML string
 * @returns {Object} Parsed metadata structure
 * @throws {Error} If XML is invalid or missing required elements
 */
export function parseSamlMetadataXml(xml) {
  if (!xml || typeof xml !== "string") {
    throw new Error("XML content is required");
  }

  let data;
  try {
    data = xmlParser.parse(xml);
  } catch (err) {
    throw new Error(`Failed to parse XML: ${err.message}`);
  }

  // Find EntityDescriptor (namespace-agnostic)
  const entityDescriptors = findAllByLocalName(data, "EntityDescriptor");

  if (!entityDescriptors.length) {
    throw new Error(
      "No EntityDescriptor found in metadata. Invalid SAML metadata.",
    );
  }

  // Usually only one EntityDescriptor; take the first
  const entityDescriptor = entityDescriptors[0];

  // Extract Entity ID
  const entityId = entityDescriptor?.["@_entityID"] || null;

  // Extract service endpoints
  const ssoServices = findAllByLocalName(
    entityDescriptor,
    "SingleSignOnService",
  )
    .map(normalizeService)
    .filter(Boolean);

  const sloServices = findAllByLocalName(
    entityDescriptor,
    "SingleLogoutService",
  )
    .map(normalizeService)
    .filter(Boolean);

  const acsServices = findAllByLocalName(
    entityDescriptor,
    "AssertionConsumerService",
  )
    .map(normalizeService)
    .filter(Boolean);

  // Extract certificates
  const certStrings = findAllByLocalName(entityDescriptor, "X509Certificate")
    .map((cert) => (typeof cert === "string" ? cert : null))
    .filter(Boolean);

  const certs = certStrings
    .map((base64) => analyzeCertificate(base64))
    .filter(Boolean);

  return {
    entityId,
    ssoServices,
    sloServices,
    acsServices,
    certs, // [{ pem, notAfter, notAfterMs }]
    raw: data,
  };
}

/**
 * Normalizes a SAML service endpoint
 * @param {Object} node - Service node from parsed XML
 * @returns {Object|null} Normalized service object
 */
function normalizeService(node) {
  if (!node || typeof node !== "object") return null;

  const binding = node["@_Binding"] || null;
  const location = node["@_Location"] || null;
  const isDefault = node["@_isDefault"];
  const index = node["@_index"];

  return {
    binding,
    location,
    isDefault: isDefault === true || isDefault === "true",
    index:
      typeof index === "string"
        ? parseInt(index, 10)
        : typeof index === "number"
          ? index
          : null,
  };
}

/**
 * Recursively finds all nodes matching a local name (ignoring namespaces)
 * @param {Object|Array} obj - Object to search
 * @param {string} targetName - Local name to find
 * @param {Array} results - Accumulator for results
 * @returns {Array} Found nodes
 */
function findAllByLocalName(obj, targetName, results = []) {
  if (obj === null || obj === undefined) return results;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      findAllByLocalName(item, targetName, results);
    }
    return results;
  }

  if (typeof obj !== "object") return results;

  for (const [key, value] of Object.entries(obj)) {
    // Extract local name (after namespace prefix)
    const localName = key.includes(":") ? key.split(":").pop() : key;

    if (localName === targetName) {
      if (Array.isArray(value)) {
        results.push(...value);
      } else {
        results.push(value);
      }
    }

    findAllByLocalName(value, targetName, results);
  }

  return results;
}

// ==================== CERTIFICATE HANDLING ====================

/**
 * Analyzes X.509 certificate from base64 DER format
 * @param {string} base64Der - Base64-encoded certificate
 * @returns {Object|null} Certificate info with PEM and expiration
 */
function analyzeCertificate(base64Der) {
  if (!base64Der || typeof base64Der !== "string") return null;

  try {
    const clean = base64Der.replace(/\s+/g, "");
    const pem = convertToPem(clean);

    // Use Node.js crypto to parse certificate
    const cert = new crypto.X509Certificate(pem);
    const notAfter = cert.validTo; // ISO date string
    const notAfterMs = Date.parse(notAfter);

    return {
      pem,
      notAfter,
      notAfterMs,
      issuer: cert.issuer,
      subject: cert.subject,
    };
  } catch (err) {
    // If parsing fails, still return PEM for manual use
    console.warn("Certificate parse warning:", err.message);
    const clean = base64Der.replace(/\s+/g, "");
    return {
      pem: convertToPem(clean),
      notAfter: null,
      notAfterMs: null,
      issuer: null,
      subject: null,
    };
  }
}

/**
 * Converts base64 DER to PEM format
 * @param {string} cleanBase64 - Clean base64 string (no whitespace)
 * @returns {string} PEM-formatted certificate
 */
function convertToPem(cleanBase64) {
  const lines = cleanBase64.match(/.{1,64}/g) || [cleanBase64];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

// ==================== SERVICE SELECTION ====================

/**
 * Picks the preferred service endpoint from a list
 * Prefers HTTP-Redirect, then HTTP-POST, then first available
 * @param {Array} services - Array of service objects
 * @returns {Object|null} Selected service or null
 */
function pickPreferredService(services) {
  if (!Array.isArray(services) || services.length === 0) return null;

  // Prefer HTTP-Redirect binding
  const redirect = services.find((s) =>
    (s.binding || "").includes("HTTP-Redirect"),
  );
  if (redirect?.location) return redirect;

  // Fallback to HTTP-POST binding
  const post = services.find((s) => (s.binding || "").includes("HTTP-POST"));
  if (post?.location) return post;

  // Return first service with location
  return services.find((s) => s.location) || null;
}

/**
 * Picks the preferred Assertion Consumer Service
 * Prefers isDefault=true, then lowest index, then first available
 * @param {Array} services - Array of ACS objects
 * @returns {Object|null} Selected ACS or null
 */
function pickPreferredAcs(services) {
  if (!Array.isArray(services) || services.length === 0) return null;

  // Prefer default ACS
  const defaultAcs = services.find((s) => s.isDefault && s.location);
  if (defaultAcs) return defaultAcs;

  // Sort by index and pick lowest
  const indexed = services
    .filter((s) => Number.isFinite(s.index) && s.location)
    .sort((a, b) => a.index - b.index);

  if (indexed.length) return indexed[0];

  // Fallback to first service with location
  return services.find((s) => s.location) || null;
}

/**
 * Picks the best certificate (latest expiration)
 * @param {Array} certs - Array of certificate objects
 * @returns {Object|null} Selected certificate or null
 */
function pickBestCertificate(certs) {
  if (!Array.isArray(certs) || certs.length === 0) return null;

  // Filter certs with valid expiration dates
  const valid = certs.filter((c) => Number.isFinite(c.notAfterMs));

  if (valid.length) {
    // Sort by expiration (latest first)
    valid.sort((a, b) => b.notAfterMs - a.notAfterMs);
    return valid[0];
  }

  // Fallback to first cert if no expiration data
  return certs[0];
}

/**
 * Detects Identity Provider from entity ID and SSO URL
 * @param {Object} params - Detection parameters
 * @returns {string} Provider name
 */
function detectProvider({ entityId, ssoUrl }) {
  const combined = `${entityId || ""} ${ssoUrl || ""}`.toLowerCase();

  if (
    combined.includes("microsoftonline.com") ||
    combined.includes("sts.windows.net")
  ) {
    return "Microsoft Entra ID (Azure AD)";
  }
  if (combined.includes("okta.com")) {
    return "Okta";
  }
  if (combined.includes("google.com")) {
    return "Google Workspace";
  }
  if (combined.includes("pingidentity") || combined.includes("pingone")) {
    return "PingIdentity";
  }
  if (combined.includes("onelogin")) {
    return "OneLogin";
  }

  return "Unknown";
}

// ==================== AUTH0 CONFIGURATION PACK ====================

/**
 * Builds Auth0-ready configuration pack from parsed metadata
 * @param {Object} params - Build parameters
 * @returns {Object} Auth0 configuration pack
 */
export function buildAuth0PastePack({ parsed, source, idpDomains = "" }) {
  const signInService = pickPreferredService(parsed.ssoServices);
  const signOutService = pickPreferredService(parsed.sloServices);
  const bestCert = pickBestCertificate(parsed.certs);

  const provider = detectProvider({
    entityId: parsed.entityId,
    ssoUrl: signInService?.location,
  });

  // Collect warnings
  const warnings = [];

  if (!parsed.entityId) {
    warnings.push("Missing Entity ID (Issuer). This is required for SAML.");
  }
  if (!signInService?.location) {
    warnings.push(
      "Missing Sign In URL (SingleSignOnService). This is required.",
    );
  }
  if (!bestCert?.pem) {
    warnings.push("Missing X.509 Signing Certificate. This is required.");
  }
  if (!signOutService?.location) {
    warnings.push("Sign Out URL not found. Single Logout may not work.");
  }

  // Certificate expiry warning
  if (bestCert?.notAfterMs) {
    const daysUntilExpiry = Math.ceil(
      (bestCert.notAfterMs - Date.now()) / (1000 * 60 * 60 * 24),
    );

    if (daysUntilExpiry <= 0) {
      warnings.push("⚠️ Certificate has expired!");
    } else if (daysUntilExpiry <= 30) {
      warnings.push(`⚠️ Certificate expires in ${daysUntilExpiry} days.`);
    } else if (daysUntilExpiry <= 90) {
      warnings.push(`Certificate expires in ${daysUntilExpiry} days.`);
    }
  }

  if (parsed.certs && parsed.certs.length > 1) {
    warnings.push(
      `Multiple certificates found (${parsed.certs.length}). Selected the one with latest expiration.`,
    );
  }

  // Default SAML attribute mappings
  const mapping = {
    email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    given_name:
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    family_name:
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
  };

  // Collect notes
  const notes = [
    `Source: ${source.type} (${source.value})`,
    `Detected Provider: ${provider}`,
    "Email mapping is critical for user identification and routing.",
  ];

  if (idpDomains?.trim()) {
    notes.push(`Suggested IdP Domains: ${idpDomains.trim()}`);
  }

  return {
    kind: "auth0",
    provider,
    fields: {
      signInUrl: signInService?.location || "",
      signOutUrl: signOutService?.location || "",
      issuer: parsed.entityId || "",
      certificate: bestCert?.pem || "",
    },
    certInfo: {
      expires: bestCert?.notAfter || null,
      issuer: bestCert?.issuer || null,
      subject: bestCert?.subject || null,
    },
    mapping,
    warnings,
    notes,
  };
}

// ==================== SERVICE PROVIDER PACK ====================

/**
 * Builds Service Provider setup pack for customer configuration
 * @param {Object} params - Build parameters
 * @returns {Object} Service Provider configuration pack
 */
export function buildServiceProviderPack({ env, identifier }) {
  if (!identifier || typeof identifier !== "string") {
    throw new Error("Identifier is required");
  }

  const cleanIdentifier = identifier.trim();
  if (!cleanIdentifier) {
    throw new Error("Identifier cannot be empty");
  }

  const envLower = (env || "").toLowerCase();

  // Determine which environments to generate
  const environments =
    envLower === "both"
      ? ["prod", "uat"]
      : envLower === "prod"
        ? ["prod"]
        : envLower === "uat"
          ? ["uat"]
          : (() => {
              throw new Error('Environment must be "prod", "uat", or "both"');
            })();

  // Generic configuration (replace with your actual domains)
  const config = {
    prod: {
      authDomain: "login.v2.researchbinders.com",
      appDomain: "login.v2.researchbinders.com",
    },
    uat: {
      authDomain: "login.uatv2.researchbinders.com",
      appDomain: "login.uatv2.researchbinders.com",
    },
  };

  const results = environments.map((e) => {
    const cfg = config[e];
    const warnings = e === "uat" ? ["Non-production environment"] : [];

    return {
      env: e.toUpperCase(),
      identifier: cleanIdentifier,
      metadataUrl: `https://${cfg.authDomain}/saml/metadata?connection=${encodeURIComponent(cleanIdentifier)}`,
      entityId: `urn:auth:example:${e}:${cleanIdentifier}`,
      acsUrl: `https://${cfg.authDomain}/login/callback?connection=${encodeURIComponent(cleanIdentifier)}`,
      landingPage: `https://${cfg.appDomain}/login`,
      warnings,
    };
  });

  return {
    kind: "service-provider",
    results,
  };
}

export default {
  fetchXmlFromUrl,
  parseSamlMetadataXml,
  buildAuth0PastePack,
  buildServiceProviderPack,
};
