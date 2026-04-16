/* =========================================================
   SSO Automation Toolkit — Backend Server
   Author: Dek Mohamud
   Description:
   Express server for parsing SAML metadata, validating
   input, and generating Auth0/SP configuration packs.
   
   Security Features:
   - Input validation and sanitization
   - File upload limits and type checking
   - Rate limiting ready
   - No data persistence
   - Memory-only file storage
   ========================================================= */

import express from "express";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";

import {
  parseSamlMetadataXml,
  buildAuth0PastePack,
  buildServiceProviderPack,
  fetchXmlFromUrl,
} from "./samlMetadata.js";

const PORT = process.env.PORT || 5500;
const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2MB
const MAX_JSON_SIZE = "2mb";
const MAX_URL_LENGTH = 2048;
const MAX_IDENTIFIER_LENGTH = 200;
const ALLOWED_ENVIRONMENTS = ["prod", "uat", "both"];

const app = express();

// Resolve __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * File upload configuration with security restrictions
 * - Memory storage only (no disk writes)
 * - 2MB file size limit
 * - XML-only file filter
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    // Validate file extension
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext !== ".xml") {
      return cb(new Error("Only XML files are allowed"));
    }

    // Validate MIME type
    const validMimeTypes = ["text/xml", "application/xml"];
    if (!validMimeTypes.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"));
    }

    cb(null, true);
  },
});

// ==================== MIDDLEWARE ====================
app.use(express.json({ limit: MAX_JSON_SIZE }));
app.use(express.urlencoded({ extended: true, limit: MAX_JSON_SIZE }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

app.use(express.static(path.join(__dirname, "public")));

// ==================== VALIDATION HELPERS ====================

/**
 * @param {string} url - URL to validate
 * @returns {boolean}
 */
function isValidUrl(url) {
  if (!url || typeof url !== "string") return false;
  if (url.length > MAX_URL_LENGTH) return false;

  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 
 * @param {string} identifier
 * @returns {boolean}
 */
function isValidIdentifier(identifier) {
  if (!identifier || typeof identifier !== "string") return false;
  if (identifier.length > MAX_IDENTIFIER_LENGTH) return false;

  // Only allow alphanumeric, hyphens, and underscores
  return /^[a-zA-Z0-9_-]+$/.test(identifier);
}

/**

 * @param {string} env
 * @returns {boolean}
 */
function isValidEnvironment(env) {
  if (!env || typeof env !== "string") return false;
  return ALLOWED_ENVIRONMENTS.includes(env.toLowerCase());
}

/**
 
 @param {string} domains - Comma-separated domains
 @returns {string}
 */
function sanitizeDomains(domains) {
  if (!domains || typeof domains !== "string") return "";

  return domains
    .replace(/[<>'"]/g, "")
    .trim()
    .substring(0, 500);
}

// ==================== ERROR HANDLER ====================

/**
 *
 * @param {Error} err - Error object
 * @param {Response} res - Express response
 * @param {string} defaultMsg
 */
function handleError(err, res, defaultMsg = "An error occurred") {
  console.error("Error:", err);

  const status = err.statusCode || 500;
  const message = err.message || defaultMsg;

  res.status(status).json({
    error: message,
    timestamp: new Date().toISOString(),
  });
}

// ==================== API ROUTES ====================

/**
 Parse IdP metadata from a remote URL
 POST /api/idp/from-url
 */
app.post("/api/idp/from-url", async (req, res) => {
  try {
    const { url, domains } = req.body ?? {};

    // Validate URL
    if (!url || typeof url !== "string") {
      return res.status(400).json({
        error: "Metadata URL is required",
      });
    }

    if (!isValidUrl(url)) {
      return res.status(400).json({
        error: "Invalid URL format. Must be HTTP or HTTPS.",
      });
    }

    // Fetch and parse metadata
    const xml = await fetchXmlFromUrl(url);

    if (!xml || typeof xml !== "string") {
      throw new Error("Failed to retrieve valid XML from URL");
    }

    const parsed = parseSamlMetadataXml(xml);

    const pack = buildAuth0PastePack({
      parsed,
      source: { type: "url", value: url },
      idpDomains: sanitizeDomains(domains),
    });

    res.json(pack);
  } catch (err) {
    handleError(err, res, "Failed to process metadata URL");
  }
});

/**
 Parse IdP metadata from uploaded XML file
 POST /api/idp/from-file
 */
app.post("/api/idp/from-file", upload.single("file"), async (req, res) => {
  try {
    // Validate file upload
    if (!req.file?.buffer) {
      return res.status(400).json({
        error: "XML file is required",
      });
    }

    if (req.file.size > MAX_FILE_SIZE) {
      return res.status(413).json({
        error: `File too large. Maximum size is ${
          MAX_FILE_SIZE / 1024 / 1024
        }MB`,
      });
    }

    const xml = req.file.buffer.toString("utf-8");

    if (!xml || xml.length === 0) {
      throw new Error("Empty or invalid XML file");
    }

    const parsed = parseSamlMetadataXml(xml);
    const domains = req.body?.domains || "";

    const pack = buildAuth0PastePack({
      parsed,
      source: {
        type: "file",
        value: path.basename(req.file.originalname), // Prevent path traversal
      },
      idpDomains: sanitizeDomains(domains),
    });

    res.json(pack);
  } catch (err) {
    handleError(err, res, "Failed to process uploaded file");
  }
});

/**
 Generate Service Provider setup pack
 POST /api/sp/generate
 Body: { env: string, identifier: string }
 */
app.post("/api/sp/generate", async (req, res) => {
  try {
    const { env, identifier } = req.body ?? {};

    // Validate identifier
    if (!identifier || typeof identifier !== "string") {
      return res.status(400).json({
        error: "Connection identifier is required",
      });
    }

    if (!isValidIdentifier(identifier)) {
      return res.status(400).json({
        error:
          "Invalid identifier. Use only letters, numbers, hyphens, and underscores.",
      });
    }

    if (!env || typeof env !== "string") {
      return res.status(400).json({
        error: "Environment is required",
      });
    }

    if (!isValidEnvironment(env)) {
      return res.status(400).json({
        error: `Invalid environment. Must be one of: ${ALLOWED_ENVIRONMENTS.join(
          ", "
        )}`,
      });
    }

    const pack = buildServiceProviderPack({
      env: env.toLowerCase(),
      identifier,
    });

    res.json(pack);
  } catch (err) {
    handleError(err, res, "Failed to generate service provider pack");
  }
});

/*
 Health check endpoint
 GET /api/health
 */
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.path,
  });
});

// ==================== GLOBAL ERROR HANDLER ====================
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);

  // Handle multer errors
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        error: `File too large. Maximum size is ${
          MAX_FILE_SIZE / 1024 / 1024
        }MB`,
      });
    }
    return res.status(400).json({ error: err.message });
  }

  // Handle other errors
  res.status(500).json({
    error: "Internal server error",
    timestamp: new Date().toISOString(),
  });
});

const server = app.listen(PORT, () => {
  console.log("=".repeat(60));
  console.log("SSO Automation Toolkit Server");
  console.log("Author: Dek Mohamud");
  console.log("=".repeat(60));
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(
    `📁 Serving static files from: ${path.join(__dirname, "public")}`
  );
  console.log(`🔒 Security: Memory-only storage, no data persistence`);
  console.log(`📊 Max file size: ${MAX_FILE_SIZE / 1024 / 1024}MB`);
  console.log("=".repeat(60));
});

process.on("SIGTERM", () => {
  console.log("Request received. Shutting down gracefully...");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("\nRequest received. Shutting down gracefully...");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

export default app;
