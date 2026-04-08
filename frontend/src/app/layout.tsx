import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Scam Detector",
  description: "AI-powered scam detection for SMS, email, and URLs",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-100">
        <nav className="border-b border-slate-800 bg-slate-900 px-6 py-4">
          <div className="max-w-6xl mx-auto flex gap-6">
            <a href="/" className="text-lg font-bold text-blue-400">
              🛡️ Scam Detector
            </a>
            <a href="/history" className="text-sm text-slate-400 hover:text-slate-200">
              Scan History
            </a>
          </div>
        </nav>
        <main className="max-w-6xl mx-auto p-6">{children}</main>
      </body>
    </html>
  );
}