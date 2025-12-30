export default function ResultCard({ email }) {
  const extracted = email.extracted || {};

  return (
    <div className="card">
      <h2>Analysis Result</h2>

      <p><strong>Status:</strong> {email.status}</p>
      <p><strong>Risk Score:</strong> {email.score}%</p>

      <h3>Extracted Header Info</h3>
      <ul>
        <li><strong>From:</strong> {extracted.fromEmail || "-"}</li>
        <li><strong>From Domain:</strong> {extracted.fromDomain || "-"}</li>
        <li><strong>Reply-To:</strong> {extracted.replyToEmail || "-"}</li>
        <li><strong>Reply-To Domain:</strong> {extracted.replyToDomain || "-"}</li>
        <li><strong>Received Hops:</strong> {extracted.receivedHops ?? "-"}</li>
      </ul>

      <h3>Triggered Indicators</h3>
      <ul>
        {email.reasons.map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
    </div>
  );
}
