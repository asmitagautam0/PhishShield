"use client";

import { useState } from "react";

export default function HeaderForm({ onAnalyze, onClear }) {
  const [emailText, setEmailText] = useState("");
  const [error, setError] = useState("");

  function handleAnalyze() {
    setError("");

    if (!emailText.trim()) {
      setError("Please paste the full email message before analyzing.");
      return;
    }

    onAnalyze({ emailText });
  }

  function handleClear() {
    setEmailText("");
    setError("");
    onClear();
  }

  return (
    <div className="card">
      <h2>Email Analyser</h2>

      <div className="field">
        <label>Paste full email message (header + body)</label>
        <textarea
          rows="16"
          value={emailText}
          onChange={(e) => setEmailText(e.target.value)}
          placeholder="Paste the complete email here..."
          style={{
            resize: "none",
            width: "100%",
          }}
        />
      </div>

      {error ? <p className="error">{error}</p> : null}

      <div style={{ display: "flex", gap: "10px", marginTop: "12px" }}>
        <button onClick={handleAnalyze}>Analyse</button>
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