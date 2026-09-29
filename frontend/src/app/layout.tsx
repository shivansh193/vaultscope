import type { Metadata } from "next";
import { Sidebar } from "@/components/Sidebar";
import { JobProvider } from "@/lib/jobs";
import "./globals.css";

export const metadata: Metadata = {
  title: "VaultScope",
  description:
    "IPsec VPN protocol analyzer and security assessment console — SIH 2026, problem statement SIH26160",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <JobProvider>
          <Sidebar />
          <main className="min-h-screen pt-[var(--mobile-bar)] md:ml-[var(--sidebar-width)]">
            {children}
          </main>
        </JobProvider>
      </body>
    </html>
  );
}
