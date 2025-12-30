export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <p>© {new Date().getFullYear()} Phishing Email Detection System</p>
        <p className="muted">Keep yourself and your surroundings phish free</p>
      </div>
    </footer>
  );
}
