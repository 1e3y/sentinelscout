import type { Metadata } from "next";

export const metadata: Metadata = {
  robots: {
    index: false,
    follow: false,
    nocache: true,
    noarchive: true,
  },
};

export default function ShareLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return children;
}
