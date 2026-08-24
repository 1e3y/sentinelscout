import type { NextConfig } from "next";
import {
  SECURITY_HEADERS,
  SHARE_SECURITY_HEADERS,
} from "./lib/security-headers";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/share",
        headers: SHARE_SECURITY_HEADERS,
      },
      {
        source: "/share/:path*",
        headers: SHARE_SECURITY_HEADERS,
      },
      {
        source: "/((?!share(?:/|$)).*)",
        headers: SECURITY_HEADERS,
      },
    ];
  },
};

export default nextConfig;
