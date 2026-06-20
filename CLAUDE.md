# Baskl / AI MACHINE — shared agent context

This file is the **shared Baskl agent context**. It is byte-identical in every Baskl
repo and synced from the canonical copy at `ai-machine/agent-docs/CLAUDE.md` via
`aim sync-docs`. Repo-specific notes live in each repo's `README.md`, imported at the
bottom of this file.

## Keeping this doc alive
- If you (an AI agent) learn something valuable about how this system works, or find
  something here that is outdated or wrong, **edit this file** and commit it. Editing it
  in any repo propagates everywhere: a pre-commit hook promotes your edit to the
  canonical copy, and every repo refreshes from canonical when you run `aim` in it (or
  run `aim sync-docs` to fan out immediately).
- Keep this file **general** — true across all repos. Put anything specific to one repo
  in that repo's `README.md` (imported below), not here.

## System overview
- Baskl ships VFX plugins for Adobe After Effects, Premiere Pro, Photoshop, and OFX
  hosts (DaVinci Resolve). Each plugin is a thin C++ layer that talks over a local API
  (shared memory by default; ws/http depending on config) to the **AIM Server**
  (`ai-machine/Server`, Python). The **AIM Client** (`ai-machine/Client`) is the static
  library all plugins build on.
- When built via CMake, a plugin essentially copies the source from
  `ai-machine/Plugins/TemplatePlugin/TemplatePlugin_Adobe` (Adobe AE/Premiere/Photoshop)
  or `TemplatePlugin_OFX` (OFX/DaVinci Resolve).
- The **installer** (`ai-machine-installer`) installs the AIM Server, RenderEngine, the
  plugins, and the models.
- **PluginTemplate** (`ai-machine/PluginTemplate`) is the template `aim init` scaffolds
  new plugins from.

## aim-cli (primary workflow)
Always use `aim-cli` — it runs from local source, always has latest changes, and skips
the update check. (`aim` is the globally-installed, auto-updating build of the same tool.)
- `aim build` — build + install plugin. Flags: `--adobe`, `--ofx`, `--both`, `--ci` (non-interactive), `--verbose`
- `aim commit` — AI-generated commit message from staged diff. Flags: `-m "context"`, `--dry-run`, `--ci`
- `aim publish` — tag, push, trigger CI. Prompts for manifest channel (prod/rc/beta). Flags: `--channel rc`, `--ci`, `--both`, `--ofx`, `--dry-run`, `--retry`, `--status`
- `aim publish --ci --channel rc --both` — non-interactive: build Adobe+OFX, publish to rc channel
- `aim publish --promote rc` — promote manifest rc to prod (no rebuild, API-only)
- `aim server --dev` — start AIM server with hot reload
- `aim install` — download release from GitHub
- `aim init` — create new plugin from the Plugin Template
- `aim fix` — regenerate release.yml, fix common issues
- `aim doctor` — check dev environment health
- `aim sync-docs` — propagate this shared doc across all Baskl repos
- `aim version --installed` — show installed plugin versions from binary
- CI/CD: `release.yml` uses `ai-machine/.github/workflows/build-plugin-reusable.yml`.
  Builds upload to baskl-releases; the manifest channel determines user visibility.

## Commits and changelog
- `CHANGELOG.md` is the single source of truth for versions.
- Before committing, update the version in `CHANGELOG.md`.
- When bumping a version, include ALL changes since the last version — check `git log`
  for commits from other contributors.
- If a version was already pushed, the next commit MUST bump to a new version — never
  edit an already-pushed CHANGELOG entry.
- If the commit isn't pushed yet, add changes via amend under the current version.
- Never add "Generated with Claude Code" or similar AI attribution to commits.

## Paths
- **Logs**: `~/.aim/logs/` — plugin logs (`<FX_NAME>.log`), server logs
  (`aim_server.log`, `aim_<plugin_id>.log`), licensing logs (`<FX_NAME>_lic_adobe.log`).
- **Read-only installed files** (plugins, server, render engine):
  `/Library/Application Support/BSKL/AI MACHINE` (mac), `C:\Program Files\BSKL\AI MACHINE` (win).
- **User-writable files** (logs, models, config, cached DLLs): `~/.aim/` — same path on
  mac, win (`C:\Users\<user>\.aim\`), linux.
- **Models**: `~/.aim/Models/`. **Config**: `~/.aim/config.json`. **Licensing** (psslic):
  `~/.aim/lic/` (legacy: `%APPDATA%\BSKL\` Roaming on Windows). **Installer-core DLL
  cache**: `~/.aim/installer/`.
- **SDKs**: OFX SDK `../plugin-dependencies/ofx-sdk`, AE SDK `../plugin-dependencies/adobe-ae-sdk`.

## Plugin render patterns
- Use `print_if_dev()` for anything that prints every frame, so we don't clog up users' logs.
- Show a progress bar with `tools.ui.progress_bar(percent: int, info: string)` — mainly
  for "loading model"; with multiple models, ramp 0–99 then 100 when finished.
- Call `tools.progress(int 0-100)` every frame to drive the host's native progress bar.
  Call it regularly while a model loads too — it prevents the client from timing out and
  keeps the user patient; do it between long steps that run every render.
- Call `tools.maybe_abort()` before any likely-slow lines: it checks if the user aborted
  in the host and exits cleanly if so. Run `aim benchmark --profile` to find slow lines.

@README.md
