"use client";

import { useState } from "react";

export default function UrlChecker() {
  const [manualUrl, setManualUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function handleCheck(e) {
    e.preventDefault();

    if (!manualUrl.trim()) {
      setResult({ status: "error", message: "Please enter a URL." });
      return;
    }

    try {
      setLoading(true);

      const res = await fetch("http://127.0.0.1:8000/api/check-url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: manualUrl.trim() })
      });

      const data = await res.json();
      setResult(data);
    } catch (err) {
      console.error("Manual URL check failed:", err);
      setResult({
        status: "error",
        message: "Could not check URL."
      });
    } finally {
      setLoading(false);
    }
  }

  function getColor(label) {
    const v = (label || "").toLowerCase();
    if (v === "malicious") return "#dc2626";
    if (v === "suspicious") return "#d97706";
    if (v === "clean") return "#16a34a";
    return "#6b7280";
  }

  return (
    <div className="card" style={{ marginTop: 24 }}>
      <h2 style={{ marginTop: 0 }}>Manual URL Checker</h2>
      <p className="muted">Paste a URL to scan it directly</p>

      <form onSubmit={handleCheck}>
        <input
          type="text"
          value={manualUrl}
          onChange={(e) => setManualUrl(e.target.value)}
          placeholder="Enter URL (https://example.com)"
          style={{
            width: "100%",
            padding: "10px",
            borderRadius: "8px",
            border: "1px solid #374151",
            marginBottom: "10px",
            background: "transparent",
            color: "white",
          }}
        />

        <button
          type="submit"
          disabled={loading}
          style={{
            padding: "8px 14px",
            borderRadius: "8px",
            border: "none",
            backgroundColor: "#2563eb",
            color: "white",
            cursor: "pointer",
          }}
        >
          {loading ? "Checking..." : "Check URL"}
        </button>
      </form>

      {result && (
        <div
          style={{
            marginTop: "12px",
            padding: "10px",
            borderRadius: "8px",
            backgroundColor: "#111827",
            border: "1px solid #374151",
          }}
        >
          {result.status === "ok" ? (
            <>
              <p style={{ margin: 0 }}>
                <strong>Status:</strong>{" "}
                <span style={{ color: getColor(result.vt_label), fontWeight: 600 }}>
                  {result.vt_label}
                </span>
              </p>

              <p style={{ marginTop: "6px", marginBottom: 0 }}>
                {result.vt_label === "malicious"
                  ? `This URL is dangerous. ${result.malicious || 0} vendors flagged it.`
                  : result.vt_label === "suspicious"
                  ? `This URL looks suspicious. ${result.suspicious || 0} vendors flagged it.`
                  : "This URL appears safe based on VirusTotal analysis."}
              </p>
            </>
          ) : (
            <p style={{ color: "#dc2626", margin: 0 }}>
              <strong>Error:</strong> {result.message || "Could not scan URL."}
            </p>
          )}
        </div>
      )}
    </div>
  );
}