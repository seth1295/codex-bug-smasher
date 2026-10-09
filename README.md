# Codex Bug Smasher

This fork adds a resumable functional bug scan to the CLI and TypeScript SDK.
It investigates ordinary correctness defects, validates evidence, and writes
Markdown and JSON reports without changing source files. The existing Standard
security scan remains available separately.

## Features

- Deep-scan repositories and selected paths with two independent discovery
  workers and one investigator subagent per worker by default.
- Find bugs in algorithms, error handling, data integrity, state transitions,
  API contracts, concurrency, and numerical edge cases.
- Keep validated bugs separate from hypotheses that still need proof; assign
  every confirmed bug a P0-P3 priority and a distinct confidence level.
- Resume saved scans and retain source coverage, validation evidence, and
  deduplication provenance.

## Quick start

Requires Node.js 22.13.0+ within 22.x, or Node.js 24.x or 26.x, Python
3.10+, and Rust 1.97.1 with Cargo to build the local plugin runtime. Python
3.10 also requires `tomli`.

This fork is distributed as source today; it is not published as
`@openai/codex-security`. Run these commands from the repository root to build
and use the checked-out CLI:

```bash
corepack pnpm --dir sdk/typescript install --frozen-lockfile
corepack pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
node plugins/codex-security/mcp-app/scripts/build_native.mjs
node plugins/codex-security/mcp-app/scripts/build_mcp_app.mjs --output plugins/codex-security/mcp --native host
corepack pnpm --dir sdk/typescript run build
node sdk/typescript/bin/codex-security.mjs login
node sdk/typescript/bin/codex-security.mjs scan /path/to/repository --mode deep --plugin-path plugins/codex-security
```

The scan uses the Codex login already available on the machine. Deep bug scans
do not require an API key, Docker, or a hosted scanner service. A report with no
validated bugs means the scan did not establish a defect in its reviewed scope;
review the saved coverage and deferred work as well.

### Scan options

Choose a scope and scan mode:

```bash
# Scan selected paths.
node sdk/typescript/bin/codex-security.mjs scan . --path src --path tests --plugin-path plugins/codex-security

# Scan committed changes from a base revision to HEAD.
node sdk/typescript/bin/codex-security.mjs scan . --diff origin/main --plugin-path plugins/codex-security

# Run a deep functional bug scan of the repository.
node sdk/typescript/bin/codex-security.mjs scan . --mode deep --plugin-path plugins/codex-security
```

Use `node sdk/typescript/bin/codex-security.mjs --help` to browse commands, or
`node sdk/typescript/bin/codex-security.mjs scan --help` for scan options and
cost limits. Deep bug scans produce reports and do not apply fixes.
Deep scans default to `gpt-6-luna` with `xhigh` reasoning; Standard scans keep
their existing model default. Explicit CLI, project, or Codex profile model
settings take precedence.

## TypeScript SDK

```ts
import { CodexSecurity } from "./sdk/typescript/dist/index.js";

const security = new CodexSecurity();

try {
  const result = await security.run("/path/to/repository", { mode: "deep" });
  console.log(result.bugFindings?.findings);
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

The [SDK guide](sdk/typescript/README.md) covers deep-scan settings, P-priority
bug results, evidence validation, coverage, and resumable reports.

## Generate SECURITY.md

Draft security guidance for a repository or one of its components:

```bash
node sdk/typescript/bin/codex-security.mjs policy . --plugin-path plugins/codex-security
node sdk/typescript/bin/codex-security.mjs policy . --path services/api --knowledge-base architecture.md --plugin-path plugins/codex-security
```

The command saves a draft outside the checkout. Review it before installing it
as guidance for future scans. See the [policy guide](sdk/typescript/docs/cli.md#generate-a-security-policy)
for supporting documents and SDK usage.

## Save and export threat models

Scans and policy generation save threat models with their results. Export a saved
model without starting another analysis:

```bash
node sdk/typescript/bin/codex-security.mjs export --scan SCAN_ID --artifact threat-model --output threatmodel.md --plugin-path plugins/codex-security
```

Omit `--scan` to use the current repository's latest completed scan. The
[export guide](sdk/typescript/docs/cli.md#exports-and-ci) also covers findings,
SARIF output for CI, and the offline TypeScript API.

## GitHub Actions

Run scheduled, manual, or pull request scans with the GitHub Action. For a weekly
repository scan, add an OpenAI API key as the repository secret
`CODEX_SECURITY_API_KEY`, then save this workflow in
`.github/workflows/codex-security.yml`. Replace `REPLACE_WITH_REVIEWED_COMMIT`
with the full SHA of an Action commit.

```yaml
name: Codex Security
on:
  workflow_dispatch:
  schedule:
    - cron: "23 7 * * 1" # Mondays at 07:23 UTC

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-24.04
    steps:
      - name: Set up the Ubuntu sandbox
        run: |
          sudo apt-get update
          sudo apt-get install --yes bubblewrap apparmor-profiles
          sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
        with:
          model: gpt-5.6-sol
          effort: high
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

Findings are report-only by default. Partial scans with valid results produce a
warning; scanner and required reporting errors fail the job. Severity thresholds
apply to complete scans.
See the [Action setup and input reference](github-action/README.md) for PR scans,
severity thresholds, and report uploads.

## Containerized bulk scans

Scan a list of repositories with the included Docker Compose configuration,
which keeps results and authentication between runs. See the
[container quick start](sdk/typescript/docs/cli.md#containerized-bulk-scans).
The [workflow runner](docker/README.md#workflow-runner) runs individual CLI stages
in containers and can connect to a separately deployed findings service.

## Findings service (preview)

Store findings, browse them in a dashboard, and review potential duplicates.
Start the local service with:

```bash
node sdk/typescript/bin/codex-security.mjs serve
```

Publish a completed scan with `publish scan --to custom`, then use `dedupe` to
review potential duplicates and save accepted groups. Point both commands at the
service with `--findings-url`. The [service guide](sdk/typescript/docs/findings-service.md)
covers setup, publishing, deduplication, and Docker deployment.

The API has no built-in authentication. Imports send complete finding JSON to
the configured embeddings endpoint and need an embedding API key, even after
ChatGPT login.

## Other providers

Scans support OpenAI, Amazon Bedrock, OpenRouter, and Fireworks AI. Bedrock uses
AWS credentials and does not require a separate OpenAI login. See
[Bedrock setup](docs/bedrock.md) for AWS profiles, regions, and model access.

For OpenRouter and Fireworks AI, set the provider's API key and choose a supported
model. See [provider configuration](sdk/typescript/docs/cli.md#native-command-authentication-and-other-providers)
for examples.

## Documentation

- [Online documentation](https://learn.chatgpt.com/docs/security/cli)
- [CLI reference](sdk/typescript/docs/cli.md)
- [Project configuration](docs/project-configuration.md)
- [Examples](examples/README.md)

To report a vulnerability privately, follow the [security policy](SECURITY.md).
