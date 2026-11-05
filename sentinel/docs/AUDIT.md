# Complete repository export audit

Prepared November 5, 2026 from hosted Sentinel version 23, revision `b3031a0973e3ffce36a0b93ff380df7d632c4130`.

This update follows the previous curated GitHub source snapshot (`1db152193c107a7ec9d76ba53f4242616daddb5e`). It preserves that export's portable Worker, Vite/Wrangler configuration, package manager, dependency versions, lockfile, secret template, and ignore rules. Current application files and assets are copied from the hosted source without redesigning or simplifying them. The complete archive contains all 73 curated project files, including source, assets, configuration, lockfile, migrations, documentation and verification scripts. It is independently usable as a new repository and needs no previous archive. No application source paths were deleted or renamed.

## Included changes

- Installation priority ordering and current globe/source geometry changes.
- Native Outlook email drafts with installation-specific alert evidence.
- Server-owned Patrick Space Force Base assignment for operator and commander, and scoped commander summaries/documents.
- Current alert comparisons below the globe and in Commander Overview, including similarity percentages, coverage and matching signals.
- Alert comparison uses current unresolved evidence and ignores CVE/product references; exercise records stay separate.
- Target-specific detection metadata and additive migration `0004_aspiring_doctor_doom.sql`, including its Drizzle snapshot/journal.
- Updated verification scripts and a fourth exposure/comparison check in the package test command.

## Repository hygiene

The original cleanup remains: unused UI-kit/connector/example scaffolding, installed dependencies, build output, caches, local databases/uploads/sessions, actual environment values, host-specific runtime wrappers, Git metadata and old archives are excluded. Logical `.openai/hosting.json` in the complete source has only DB/R2 binding names and no live hosted project identity. Application secrets are server environment values, with blank placeholders in `.env.example`.

The archive includes all portable configuration files. Dependency inputs and package versions remain unchanged from the previously curated export. It contains no production reports, contacts, AAR/COA records, sessions or uploaded logs.

## Validation of the assembled updated source

Checks ran against a separate assembled source copy, reusing the already installed dependencies from the previous curated lockfile. Node 24.22.1 was used. No package versions changed. A fresh dependency install could not be confirmed here because the managed offline package metadata was unavailable; the following checks ran the installed tool binaries and the exact project verification scripts directly.

| Check | Result |
| --- | --- |
| TypeScript `tsc --noEmit` | Passed |
| `scripts/verify-map.mjs` | Passed |
| `scripts/verify-evidence.mjs` | Passed, including current API/authentication/commander and additive migrations |
| `scripts/verify-intel.mjs` | Passed |
| `scripts/verify-exposure.mjs` | Passed: current alerts, CVE independence, scope, behavior thresholds, scoring and coverage |
| Vinext production build | Passed |

No fresh browser/runtime session or new cloud deployment was performed for this complete source export. Lint was not rerun; the previous audit documented existing lint debt. Source/ZIP checks exclude secrets, dependencies, build outputs, Git metadata, caches, nested archives and duplicate project copies. All 54 product/source, asset, schema/migration and verification files are confirmed byte-identical to the current hosted source revision. The complete ZIP is verified against the assembled source tree.

## Creating the new repository

Use GitHub Desktop to create a new local repository with a unique name. Copy all contents of the extracted `sentinel` folder into the new repository root, including the hidden configuration/template files. Preserve the Git metadata created by Desktop. Commit the files and choose Publish repository to create the remote on GitHub. The README contains the complete walkthrough and local development instructions.

The archive contains no `.git/` history or live hosted project identity. Pushing it creates a source repository and does not migrate hosted data or automatically deploy the existing Site. Configure a new Cloudflare deployment, resource IDs and private environment values separately if desired. Licensing and branding permissions remain owner decisions described in the README.
