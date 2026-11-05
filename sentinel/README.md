# Sentinel

Sentinel is a shared cyber activity dashboard for reporting alerts against a fixed catalog of 15 U.S. military installations. It maps reported sources and targets on an interactive globe and provides a separate commander overview.

This repository contains the application source. Existing hosted reports, uploaded logs, contacts, sessions, and commander documents live in external storage and are not included.

## Features

- Password-protected team workspace and separately protected commander overview.
- Interactive globe, installation details, source enrichment, and reported source-to-target activity.
- Log ingestion with field extraction, pattern detection, validation against approved installations, and duplicate prevention.
- CISA, SANS, and NIST threat intelligence with five-minute refresh and server-side caching.
- Commander summaries, charts, reports, and editable AAR/COA drafts.
- Responsive layouts, installation contacts, and Outlook draft links with relevant alert information.
- One Patrick Space Force Base home assignment for the operator and commander.
- Current alert comparison below the globe, with alert-based similarity percentages, data coverage, and matching signals. Resolved reports and CVE/product references do not contribute to the comparison.

## Technology

React 19, TypeScript, Vinext 1.0.0-beta.5, Vite 8, Tailwind CSS 4, and Lucide icons. The backend runs in Cloudflare Workers with D1 (SQLite) and R2. Drizzle maintains the database schema and migrations. pnpm manages dependencies.

Vinext implements the Next.js App Router conventions used here. This is a server application; GitHub Pages cannot host its API, authentication, database, or log storage.

## Structure

```text
sentinel/
├── app/                   # Pages, feature components, styles, API route
├── lib/                   # Parsing, analysis, catalog, auth/API, feeds, metadata
├── db/schema.ts           # Drizzle schema
├── drizzle/               # Ordered SQL migrations and migration metadata
├── public/                # Used branding, globe geometry, map attribution
├── worker/index.ts        # Cloudflare request entry point
├── scripts/               # Feature checks and licensed Sites build integration
├── docs/AUDIT.md           # Cleanup scope, validation, known limitations
├── .openai/hosting.json    # Logical binding manifest; no live project identity
├── .env.example           # Empty local secret template
├── package.json
├── pnpm-lock.yaml
├── pnpm-workspace.yaml
├── vite.config.ts
└── wrangler.jsonc          # Local bindings and deployment placeholders
```

## Prerequisites

- Node.js 22.13 or newer; validation versions are recorded in the audit.
- pnpm **11.25.0** (`npm install --global pnpm@11.25.0` if needed).
- A Cloudflare account with Workers, D1, and R2 enabled for deployment. Local development uses emulated resources and does not need production credentials.

## Install and run locally

From the extracted `sentinel` directory:

```bash
pnpm install --frozen-lockfile
cp .env.example .dev.vars
```

On Windows PowerShell, use `Copy-Item .env.example .dev.vars` instead of `cp`.

Edit `.dev.vars` and set two different private values:

| Variable | Purpose |
| --- | --- |
| `SITE_PASSWORD` | Team workspace login |
| `COMMANDER_PASSWORD` | Additional commander login |

The empty template deliberately contains no working passwords. Wrangler loads `.dev.vars` into the server runtime; these values must never become frontend variables or be committed. `DB` and `BUCKET` are resource bindings configured in `wrangler.jsonc`, not secret strings to paste into the template.

Apply the complete migration chain, then start development:

```bash
pnpm db:migrate:local
pnpm dev
```

Open `http://localhost:5173`. Log in with your local team password; the commander page also requires your local commander password. Local database and uploaded-log state are stored under the ignored `.wrangler/` directory. Do not delete it if you want to retain local test data.

## Checks and production build

```bash
pnpm typecheck
pnpm test
pnpm build
pnpm preview
```

The preview runs the built Worker at `https://127.0.0.1:4173`, using the same local storage. Its self-signed local certificate may require a browser exception. HTTPS preserves the production secure-cookie behavior; development uses HTTP-compatible local cookies.

`pnpm start` is an alias for this local production preview. Rebuild before previewing changed source, resource configuration, or `.dev.vars` values. `pnpm deploy` automatically builds before publishing. Build output is generated in `dist/` and excluded from version control. The build tool can copy local secrets into `dist/server/.dev.vars` for preview; keep the entire generated directory private and out of exports.

`pnpm test` runs the map, ingestion/API, authentication, commander, threat-feed, and current-alert comparison checks. The API/feed checks use isolated SQLite/R2 fixtures and synthetic test credentials. `pnpm lint` currently reports existing application lint debt; it is retained as a maintenance check. Findings are recorded in [the audit](docs/AUDIT.md).

## Deploy a new instance

1. Authenticate and create resources. Choose unique resource names if these are already taken in your account:

   ```bash
   pnpm exec wrangler login
   pnpm exec wrangler d1 create sentinel-db
   pnpm exec wrangler r2 bucket create sentinel-logs
   ```

2. Update `wrangler.jsonc` with your Worker name, D1 database name/ID returned above, and R2 bucket name. Keep the binding names `DB` and `BUCKET`. The checked-in all-zero database ID is a local placeholder.

3. Set the final public HTTPS origin in **both** `lib/site-metadata.ts` and the footer in `lib/outlook-draft.ts`. The export preserves the current hosted origin to keep application behavior unchanged. These two values control sharing metadata and links in draft emails; they do not contain credentials.

4. Apply migrations to your **new** database and configure server secrets interactively:

   ```bash
   pnpm db:migrate:remote
   pnpm exec wrangler secret put SITE_PASSWORD --config wrangler.jsonc
   pnpm exec wrangler secret put COMMANDER_PASSWORD --config wrangler.jsonc
   ```

5. Build and deploy:

   ```bash
   pnpm deploy
   ```

6. Verify the deployed team and commander logins, report ingestion, globe, contact links, and threat feed. Configure your custom domain in Cloudflare if desired. Production must use HTTPS.

Cloudflare may require confirmation when creating a Worker for the first secret. Production secrets are managed independently from `.dev.vars`; never pass passwords on the command line or store them in GitHub source.

For schema changes, update `db/schema.ts`, run `pnpm db:generate`, review the resulting SQL, and commit both the SQL and Drizzle metadata. Apply new migrations locally before targeting production.

## Create a new GitHub repository with GitHub Desktop

1. Extract the complete ZIP and open the inner `sentinel` directory.
2. In GitHub Desktop, choose **File → New repository**. Pick a unique repository name and a local parent directory. Leave the README option unchecked and the Git ignore/License selections at None because the source includes its own README and ignore rules.
3. Choose **Repository → Show in Explorer** (or Show in Finder). Enable hidden files so `.gitignore`, `.env.example`, and `.openai/` are included when copying.
4. Copy everything inside the extracted `sentinel` directory into the new repository root. The root should directly contain `package.json`, `README.md`, `app/`, `lib/`, and `public/`. Keep the `.git/` directory created by GitHub Desktop.
5. Review the Changes list and commit with the summary `Import latest Sentinel source`.
6. Click **Publish repository**, choose the GitHub owner and visibility, and publish. GitHub Desktop creates the remote repository and uploads the committed files.
7. Choose **Repository → View on GitHub** and verify the folders and README are present. Invite collaborators in the repository settings if needed.

This is a complete source snapshot, not an update-only bundle. It needs no older ZIP or previous repository. No installed dependencies, build output, actual secrets, production logs, database records, or Git history are included. Creating/pushing a GitHub repository does not automatically deploy the website; use the deployment instructions above for a separate hosting setup.

## Before operational use

The existing access model uses shared passwords, including the additional commander gate. It does not establish individual identity or role membership. Plan identity-based access separately if your operational requirements call for it. Pattern results describe submitted evidence and require analyst review.

Installation POC defaults intentionally use non-deliverable `example.invalid` email addresses. Update contacts before sending real coordination emails. Existing production D1/R2 data requires a separate, authorized migration and should not be committed to a repository.

No project-wide open-source license was supplied. Choose an appropriate license and confirm permissions for supplied branding before public distribution. Retained third-party notices accompany their files; map attribution is in `public/map-attribution.txt`.

## Source snapshot

This complete export follows hosted Sentinel version 23, source revision `b3031a0973e3ffce36a0b93ff380df7d632c4130` (November 5, 2026). It includes Patrick Space Force Base membership, current alert comparisons based on alerts rather than CVEs, the interactive globe, commander view, Outlook drafts, and the public intelligence feed. The portable repository retains its existing development and deployment configuration. The application files are identical to the current hosted source; the project identity and environment secrets remain excluded.
