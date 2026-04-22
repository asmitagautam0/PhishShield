"use client";

import { useState } from "react";

export default function ResultCard({ email }) {
  const [openIndex, setOpenIndex] = useState(null);

  const extracted = email.extracted || {};
  const auth = email.emailAuthenticationResult || {};
  const urlResults = email.urlResults || [];
  const urlsFound = email.urlsFound || [];

  const status = email.status || "Unknown";
  const reasons = email.reasons || [];
  const message = email.message || "";

  const isInsufficientInput = status === "Insufficient Input";

  const getStatusColor = (value) => {
    if (value === "Phishing") return "#dc2626";
    if (value === "Suspicious") return "#d97706";
    if (value === "Safe") return "#16a34a";
    if (value === "Insufficient Input") return "#2563eb";
    return "#6b7280";
  };

  const getAuthColor = (value) => {
    if (value === "pass") return "#16a34a";
    if (value === "fail") return "#dc2626";
    if (value === "softfail" || value === "neutral") return "#d97706";
    return "#6b7280";
  };

  const getVTColor = (value) => {
    const v = (value || "").toLowerCase();
    if (v === "malicious") return "#dc2626";
    if (v === "suspicious") return "#d97706";
    if (v === "clean") return "#16a34a";
    return "#6b7280";
  };

  const badgeStyle = {
    display: "inline-block",
    padding: "4px 10px",
    borderRadius: "999px",
    fontWeight: "600",
    fontSize: "12px",
    color: "white",
  };

  const sectionStyle = {
    marginTop: "20px",
  };

  const warningBoxStyle = {
    marginTop: "14px",
    padding: "12px 14px",
    borderRadius: "10px",
    backgroundColor: "#172554",
    border: "1px solid #2563eb",
    color: "#dbeafe",
    fontWeight: "500",
  };

  const infoBoxStyle = {
    marginTop: "14px",
    padding: "12px 14px",
    borderRadius: "10px",
    backgroundColor: "#0f172a",
    border: "1px solid #1f2937",
  };

  const vtBadge = (value) => (
    <span
      style={{
        ...badgeStyle,
        backgroundColor: getVTColor(value),
        flexShrink: 0,
      }}
    >
      {value || "unknown"}
    </span>
  );

  const authBadge = (label, value) => (
    <span
      style={{
        ...badgeStyle,
        backgroundColor: getAuthColor((value || "unknown").toLowerCase()),
        marginRight: "10px",
        marginBottom: "10px",
      }}
    >
      {label}: {value || "unknown"}
    </span>
  );

  const getVTMessage = (item) => {
    if (!item) return "No report available.";

    if (item.status !== "ok") {
      return item.message || "Could not analyze this URL.";
    }

    if (item.vt_label === "malicious") {
      return `This URL is dangerous. ${item.malicious} security vendors flagged it as malicious.`;
    }

    if (item.vt_label === "suspicious") {
      return `This URL looks suspicious. ${item.suspicious} vendors raised concerns.`;
    }

    return "This URL appears safe based on current scan results.";
  };

  return (
    <div className="card">
      <h2>Analysis Result</h2>

      <p>
        <strong>Status:</strong>{" "}
        <span
          style={{
            ...badgeStyle,
            backgroundColor: getStatusColor(status),
          }}
        >
          {status}
        </span>
      </p>

      {!isInsufficientInput && (
        <p>
          <strong>Risk Score:</strong> {email.score}%
        </p>
      )}

      {(message || isInsufficientInput) && (
        <div style={warningBoxStyle}>
          {message || "Please paste the full email message for accurate analysis."}
        </div>
      )}

      {!isInsufficientInput && reasons.length > 0 && (
        <div style={sectionStyle}>
          <h3>Triggered Indicators</h3>
          <ul>
            {reasons.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>
        </div>
      )}

      {!isInsufficientInput && (
        <>
          <div style={sectionStyle}>
            <h3>Email Authentication</h3>
            {authBadge("SPF", auth.spf)}
            {authBadge("DKIM", auth.dkim)}
            {authBadge("DMARC", auth.dmarc)}
          </div>

          <div style={sectionStyle}>
            <h3>Extracted Header Info</h3>
            <ul>
              <li>
                <strong>Subject:</strong> {extracted.subject || "-"}
              </li>
              <li>
                <strong>From:</strong> {extracted.fromEmail || "-"}
              </li>
              <li>
                <strong>From Domain:</strong> {extracted.fromDomain || "-"}
              </li>
              <li>
                <strong>Reply-To:</strong> {extracted.replyToEmail || "-"}
              </li>
              <li>
                <strong>Reply-To Domain:</strong> {extracted.replyToDomain || "-"}
              </li>
            </ul>
          </div>

          <div style={sectionStyle}>
            <h3>URLs Found</h3>

            {urlsFound.length === 0 && (
              <p style={{ color: "#6b7280" }}>No URLs found</p>
            )}

            {urlsFound.map((url, index) => {
              const report = urlResults[index];
              const isOpen = openIndex === index;

              return (
                <div key={index} style={{ marginBottom: "10px" }}>
                  <div
                    onClick={() => setOpenIndex(isOpen ? null : index)}
                    style={{
                      cursor: "pointer",
                      padding: "10px",
                      border: "1px solid #1f2937",
                      borderRadius: "8px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      backgroundColor: isOpen ? "#0f172a" : "transparent",
                      gap: "10px",
                    }}
                  >
                    <span style={{ wordBreak: "break-all", flex: 1 }}>{url}</span>
                    {report && vtBadge(report.vt_label)}
                  </div>

                  {isOpen && report && (
                    <div
                      style={{
                        marginTop: "6px",
                        padding: "10px",
                        borderLeft: "2px solid #1f2937",
                        backgroundColor: "#020617",
                        borderRadius: "6px",
                      }}
                    >
                      <p style={{ margin: 0, marginBottom: "6px" }}>
                        {getVTMessage(report)}
                      </p>

                      {report.status === "ok" ? (
                        <ul style={{ margin: 0, paddingLeft: "18px" }}>
                          <li>Malicious: {report.malicious}</li>
                          <li>Suspicious: {report.suspicious}</li>
                          <li>Harmless: {report.harmless}</li>
                          <li>Undetected: {report.undetected}</li>
                        </ul>
                      ) : (
                        <p style={{ color: "#dc2626", margin: 0 }}>
                          <strong>Error:</strong>{" "}
                          {report.message || "Could not fetch VirusTotal report."}
                        </p>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      
    </div>
  );
}