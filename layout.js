import "./globals.css";
import ClientLayout from "../components/ClientLayout";



export const metadata = {
  title: "Phishing Email Detection System",
  description: "Rule-based phishing detection (ML planned)",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <ClientLayout>{children}</ClientLayout>
      </body>
    </html>
  );
}
