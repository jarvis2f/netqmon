import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

const nextConfig: NextConfig = {
  output: "standalone",
  distDir: process.env.NETQMON_NEXT_DIST_DIR ?? ".next",
};

export default withNextIntl(nextConfig);
