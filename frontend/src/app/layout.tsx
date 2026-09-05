import type { Metadata } from "next";
import { Sidebar } from "@/components/Sidebar";
import "./globals.css";

export const metadata: Metadata = {
  title: "VaultScope",
  description: "IPsec VPN protocol analyzer and security assessment console",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Sidebar />
        <main className="ml-[var(--sidebar-width)] min-h-screen">{children}</main>
      </body>
    </html>
  );
}
