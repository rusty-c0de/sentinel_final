import vinext from "vinext";
import { defineConfig } from "vite";
import { cloudflare } from "@cloudflare/vite-plugin";
import { sites } from "./scripts/vite/sites-vite-plugin";

export default defineConfig({
  plugins: [
    vinext(),
    sites({ mockAuth: false }),
    cloudflare({
      configPath: "./wrangler.jsonc",
      viteEnvironment: { name: "rsc", childEnvironments: ["ssr"] },
      inspectorPort: false,
    }),
  ],
});
