import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  buildAuth0PastePack,
  parseSamlMetadataXml,
  fetchXmlFromUrl,
} from "./samlMetadata.js";

const DAY_MS = 1000 * 60 * 60 * 24;

function minimalParsed(overrides = {}) {
  const now = Date.now();
  return {
    entityId: "https://idp.example.com/metadata",
    ssoServices: [
      {
        binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        location: "https://idp.example.com/sso",
      },
    ],
    sloServices: [],
    acsServices: [],
    certs: [
      {
        pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        notAfter: new Date(now + 365 * DAY_MS).toISOString(),
        notAfterMs: now + 365 * DAY_MS,
        issuer: "CN=test",
        subject: "CN=test",
      },
    ],
    attributes: [],
    ...overrides,
  };
}

describe("buildAuth0PastePack", () => {
  it("marks cert urgency expired when notAfter is in the past", () => {
    const now = Date.now();
    const parsed = minimalParsed({
      certs: [
        {
          pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
          notAfter: new Date(now - 2 * DAY_MS).toISOString(),
          notAfterMs: now - 2 * DAY_MS,
          issuer: "CN=old",
          subject: "CN=old",
        },
      ],
    });
    const pack = buildAuth0PastePack({
      parsed,
      source: { type: "file", value: "fixture.xml" },
    });
    assert.equal(pack.certInfo.urgency, "expired");
    assert.equal(pack.certInfo.daysUntilExpiry <= 0, true);
    assert.ok(pack.warnings.some((w) => /expired/i.test(w)));
  });

  it("marks cert urgency soon when within 30 days", () => {
    const now = Date.now();
    const parsed = minimalParsed({
      certs: [
        {
          pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
          notAfter: new Date(now + 10 * DAY_MS).toISOString(),
          notAfterMs: now + 10 * DAY_MS,
          issuer: "CN=s",
          subject: "CN=s",
        },
      ],
    });
    const pack = buildAuth0PastePack({
      parsed,
      source: { type: "file", value: "fixture.xml" },
    });
    assert.equal(pack.certInfo.urgency, "soon");
    assert.ok(
      pack.certInfo.daysUntilExpiry >= 1 && pack.certInfo.daysUntilExpiry <= 30
    );
    assert.ok(pack.warnings.some((w) => /expires in \d+ days/i.test(w)));
  });

  it("marks cert urgency ok when more than 30 days remain", () => {
    const now = Date.now();
    const parsed = minimalParsed({
      certs: [
        {
          pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
          notAfter: new Date(now + 120 * DAY_MS).toISOString(),
          notAfterMs: now + 120 * DAY_MS,
          issuer: "CN=ok",
          subject: "CN=ok",
        },
      ],
    });
    const pack = buildAuth0PastePack({
      parsed,
      source: { type: "file", value: "fixture.xml" },
    });
    assert.equal(pack.certInfo.urgency, "ok");
    assert.ok(pack.certInfo.daysUntilExpiry > 30);
  });

  it("marks cert urgency unknown when best cert has no notAfterMs", () => {
    const parsed = minimalParsed({
      certs: [
        {
          pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
          notAfter: null,
          notAfterMs: null,
          issuer: null,
          subject: "CN=opaque",
        },
      ],
    });
    const pack = buildAuth0PastePack({
      parsed,
      source: { type: "file", value: "fixture.xml" },
    });
    assert.equal(pack.certInfo.urgency, "unknown");
    assert.equal(pack.certInfo.daysUntilExpiry, null);
  });

  it("counts requested vs metadata-only attributes in attributeExtraction", () => {
    const parsed = minimalParsed({
      attributes: [
        { name: "urn:email", friendlyName: null, source: "metadata" },
        { name: "urn:givenName", friendlyName: null, source: "requested" },
        { name: "urn:both", friendlyName: null, source: "both" },
      ],
    });
    const pack = buildAuth0PastePack({
      parsed,
      source: { type: "url", value: "https://idp.example.com/metadata" },
    });
    assert.equal(pack.attributeExtraction.totalCount, 3);
    assert.equal(pack.attributeExtraction.requestedAttributeCount, 2);
    assert.equal(pack.attributeExtraction.metadataAttributeCount, 1);
  });
});

describe("parseSamlMetadataXml", () => {
  it("throws when XML is empty", () => {
    assert.throws(() => parseSamlMetadataXml(""), /required/i);
  });

  it("dedupes Attribute and RequestedAttribute by Name with source both", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    <Attribute Name="urn:email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
    <RequestedAttribute Name="urn:email" FriendlyName="mail" isRequired="true"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
    const parsed = parseSamlMetadataXml(xml);
    assert.equal(parsed.attributes.length, 1);
    assert.equal(parsed.attributes[0].name, "urn:email");
    assert.equal(parsed.attributes[0].source, "both");
    assert.equal(parsed.attributes[0].friendlyName, "mail");
  });
});

describe("fetchXmlFromUrl", () => {
  it("rejects non-http protocols", async () => {
    await assert.rejects(
      () => fetchXmlFromUrl("ftp://example.com/x"),
      /HTTP and HTTPS/i
    );
  });
});
