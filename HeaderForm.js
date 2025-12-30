"use client";

import { useState } from "react";

export default function HeaderForm({ onAnalyze, onClear }) {
  const [headerText, setHeaderText] = useState("");
  const [error, setError] = useState("");

  function handleAnalyze() {
    setError("");
    if (!headerText.trim()) {
      setError("Please paste the email header before analyzing.");
      return;
    }
    onAnalyze({ headerText });
  }

  function handleClear() {
    setHeaderText("");
    setError("");
    onClear();
  }

  return (
    <div className="card">
      <h2>Email Analyzer</h2>
      <p className="muted">Paste full email header or email text and click Analyze.</p>

      <div className="field">
        <label>Email Header *</label>
        <textarea
          rows="14"
          value={headerText}
          onChange={(e) => setHeaderText(e.target.value)}
          placeholder="Paste email header here..."
        />
      </div>

      {error ? <p className="error">{error}</p> : null}

      <div style={{ display: "flex", gap: "10px", marginTop: "12px" }}>
        <button onClick={handleAnalyze}>Analyze</button>
        <button
          onClick={handleClear}
          style={{ background: "#1d2a44", border: "1px solid #22304a" }}
        >
          Clear
        </button>
      </div>
    </div>
  );
}
