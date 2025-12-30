"use client";

import { useState } from "react";
import HeaderForm from "../../components/HeaderForm";
import ResultCard from "../../components/ResultCard";

/* ---------------- Helper Functions ---------------- */

function getHeaderLine(text, key) {
  const lines = text.split(/\r?\n/);
  const found = lines.find((l) => l.toLowerCase().startsWith(key.toLowerCase() + ":"));
  return found ? found.split(":").slice(1).join(":").trim() : "";
}

function extractEmail(text) {
  if (!text) return "";
  const match = text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0] : "";
}

function extractDomainFromEmail(email) {
  if (!email || !email.includes("@")) return "";
  return email.split("@")[1].toLowerCase();
}

function getUrls(rawText) {
  const urlRegex = /(https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+)/gi;
  return rawText.match(urlRegex) || [];
}

function getHostname(url) {
  try {
    let u = url.trim();
    if (u.toLowerCase().startsWith("www.")) u = "http://" + u;
    const host = new URL(u).hostname.toLowerCase();
    return host;
  } catch {
    // fallback: best-effort extraction
    return url
      .replace(/^https?:\/\//i, "")
      .split(/[\/?#]/)[0]
      .toLowerCase();
  }
}

function looksLikeIPAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function countExcessivePunctuation(s) {
  const exclamations = (s.match(/!/g) || []).length;
  const question = (s.match(/\?/g) || []).length;
  return exclamations + question;
}

function uppercaseRatio(s) {
  if (!s || s.length === 0) return 0;
  const upper = s.replace(/[^A-Z]/g, "").length;
  return upper / s.length;
}

function hasUnicodeLookalikes(s) {
  // Very simple: flags if non-ASCII characters exist (common in homoglyph attacks).
  // Not perfect, but useful as a heuristic.
  return /[^\x00-\x7F]/.test(s);
}

function isShortener(host) {
  const shorteners = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
  ]);
  return shorteners.has(host);
}

/* ---------------- Rule-Based Analysis (General) ---------------- */

function ruleBasedEmailAnalysis(rawText) {
  const raw = rawText || "";
  const text = raw.toLowerCase();

  let score = 0;
  const reasons = [];

  // --- Extract From / Reply-To / Subject when available (works for headers OR full text) ---
  const fromLine = getHeaderLine(raw, "From");
  const replyToLine = getHeaderLine(raw, "Reply-To");
  const subjectLine = getHeaderLine(raw, "Subject");
  const authLine = getHeaderLine(raw, "Authentication-Results");

  const fromEmail = extractEmail(fromLine) || extractEmail(raw);
  const replyToEmail = extractEmail(replyToLine);

  const fromDomain = extractDomainFromEmail(fromEmail);
  const replyToDomain = extractDomainFromEmail(replyToEmail);

  // --- 1) Urgency / Threat / Pressure language ---
  const urgencyTerms = [
    "urgent",
    "immediately",
    "act now",
    "final warning",
    "within 24 hours",
    "within 48 hours",
    "limited time",
    "account will be suspended",
    "account will be closed",
    "your account has been locked",
    "suspended",
    "blocked",
    "verify immediately",
    "failure to act",
  ];
  if (urgencyTerms.some((t) => text.includes(t))) {
    score += 20;
    reasons.push("Urgency/threat language detected");
  }

  // --- 2) Credential / verification / personal info request ---
  const credentialTerms = [
    "verify your identity",
    "verify your account",
    "confirm your account",
    "update your password",
    "reset your password",
    "login",
    "sign in",
    "otp",
    "one-time password",
    "security code",
    "confirm your details",
    "billing information",
    "payment information",
  ];
  if (credentialTerms.some((t) => text.includes(t))) {
    score += 25;
    reasons.push("Credential/verification request detected");
  }

  // --- 3) Suspicious attachments ---
  const attachmentTerms = ["attachment:", "attached", ".pdf", ".doc", ".docx", ".zip", ".rar", ".exe", ".js"];
  const suspiciousAttachment = attachmentTerms.some((t) => text.includes(t));
  if (suspiciousAttachment) {
    score += 10;
    reasons.push("Attachment mentioned or file type detected");
    // if paired with credential/verify language, increase risk
    if (credentialTerms.some((t) => text.includes(t))) {
      score += 10;
      reasons.push("Attachment combined with verification theme");
    }
  }

  // --- 4) Link analysis ---
  const urls = getUrls(raw);
  if (urls.length > 0) {
    score += 10;
    reasons.push(`Link(s) present (${urls.length})`);
  }

  // Evaluate each URL
  let shortenerFound = false;
  let ipUrlFound = false;
  let manySubdomainFound = false;
  let atSymbolTrickFound = false;

  for (const u of urls) {
    const host = getHostname(u);

    // Shortened URLs
    if (isShortener(host)) shortenerFound = true;

    // IP address as host
    if (looksLikeIPAddress(host)) ipUrlFound = true;

    // Many subdomains (often used to hide true domain)
    const parts = host.split(".");
    if (parts.length >= 4) manySubdomainFound = true;

    // @ trick in URL (user@host can mislead users)
    if (u.includes("@")) atSymbolTrickFound = true;
  }

  if (shortenerFound) {
    score += 20;
    reasons.push("Shortened URL detected");
  }
  if (ipUrlFound) {
    score += 25;
    reasons.push("URL uses IP address instead of domain");
  }
  if (manySubdomainFound) {
    score += 15;
    reasons.push("Suspicious URL structure (many subdomains)");
  }
  if (atSymbolTrickFound) {
    score += 15;
    reasons.push("Suspicious URL contains '@' (possible deception)");
  }

  // --- 5) Sender domain risk heuristics ---
  // Free email domains are not always phishing, but role-based names + free domains are suspicious.
  const freeDomains = new Set(["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"]);
  const roleTerms = ["support", "security", "billing", "admin", "service", "helpdesk", "no-reply", "noreply"];

  if (fromDomain && freeDomains.has(fromDomain)) {
    const fromLower = fromLine.toLowerCase();
    const looksRoleBased = roleTerms.some((t) => fromLower.includes(t));
    score += looksRoleBased ? 20 : 10;
    reasons.push(
      looksRoleBased
        ? `Role-based sender on free email domain (${fromDomain})`
        : `Sender uses free email domain (${fromDomain})`
    );
  }

  // From vs Reply-To mismatch
  if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
    score += 20;
    reasons.push("From domain and Reply-To domain mismatch");
  }

  // Non-ASCII characters (homoglyph risk)
  if (hasUnicodeLookalikes(raw)) {
    score += 10;
    reasons.push("Non-ASCII characters detected (possible lookalike text)");
  }

  // --- 6) Formatting anomalies ---
  if (countExcessivePunctuation(raw) > 8) {
    score += 10;
    reasons.push("Excessive punctuation detected");
  }
  if (uppercaseRatio(raw) > 0.35) {
    score += 10;
    reasons.push("Excessive uppercase text detected");
  }

  // --- 7) Authentication results (if header provided) ---
  const auth = (authLine || "").toLowerCase();
  if (auth.includes("spf=fail")) {
    score += 20;
    reasons.push("SPF failed");
  }
  if (auth.includes("dkim=fail")) {
    score += 20;
    reasons.push("DKIM failed");
  }
  if (auth.includes("dmarc=fail")) {
    score += 20;
    reasons.push("DMARC failed");
  }

  // --- 8) Subject-based risk (if present) ---
  const subj = (subjectLine || "").toLowerCase();
  if (subj) {
    const suspiciousSubjectTerms = ["urgent", "verify", "action required", "account", "suspended", "locked"];
    if (suspiciousSubjectTerms.some((t) => subj.includes(t))) {
      score += 10;
      reasons.push("Suspicious subject keywords detected");
    }
  }

  // Cap score 0..100
  score = Math.max(0, Math.min(100, score));

  // Final classification
  let status = "Safe";
  if (score >= 70) status = "Phishing";
  else if (score >= 40) status = "Suspicious";

  if (reasons.length === 0) reasons.push("No common phishing indicators detected");

  return {
    score,
    status,
    reasons,
    extracted: {
      fromEmail: fromEmail || "-",
      fromDomain: fromDomain || "-",
      replyToEmail: replyToEmail || "-",
      replyToDomain: replyToDomain || "-",
      subject: subjectLine || "-",
      detectedLinks: urls.length,
    },
  };
}

/* ---------------- Page Component ---------------- */

export default function AnalyzerPage() {
  const [result, setResult] = useState(null);

  function handleAnalyze({ headerText }) {
    setResult(ruleBasedEmailAnalysis(headerText));
  }

  function handleClear() {
    setResult(null);
  }

  return (
    <main>
      <div className="card">
        <h1 style={{ marginTop: 0 }}>Hybrid Phishing Detection Tool</h1>
        <p className="muted">
          Combination of both rule-based system and machine-learning classification model.
        </p>
      </div>

      <HeaderForm onAnalyze={handleAnalyze} onClear={handleClear} />

      {result && <ResultCard email={result} />}
    </main>
  );
}
