import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

const nextConfig: NextConfig = {
  output: "standalone",
  // The local IDEA server is accessed from other devices on the LAN.
  // Allow Next's development assets and HMR requests from that origin.
  allowedDevOrigins: ["192.168.2.80", "localhost", "127.0.0.1"],
};

export default withNextIntl(nextConfig);
