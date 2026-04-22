export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <p>© {new Date().getFullYear()} Phishing Email Detection System</p>
        <p className="muted">Be aware of hackers</p>
      </div>
    </footer>
  );
}
