import { ClerkProvider } from "@clerk/nextjs";

export default function AppLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return <ClerkProvider>{children}</ClerkProvider>;
}
