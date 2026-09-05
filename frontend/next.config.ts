import type { NextConfig } from "next";

/**
 * Static export: the console is entirely client-side (it talks to FastAPI from
 * the browser), so nginx can serve the built files directly -- no Node runtime
 * in the frontend container. Session drilldown is a panel rather than a
 * dynamic route, which keeps every page statically renderable.
 */
const nextConfig: NextConfig = {
  output: "export",
  images: { unoptimized: true },
};

export default nextConfig;
