# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — Agent Audit & Patch Prompt

**How to use:** Fill in the `[ ]` placeholders for the project you're running this
against, then paste the whole thing into your coding agent (Claude Code, Cursor,
Copilot Workspace, Antigravity etc.) from the repo root. Works on any PHP project —
Dockerized or not, single-service or multi-tenant.

---

## Prompt

```
I need to audit and, once confirmed, patch this codebase against a critical
PHP core vulnerability: PHP2Shell (CVE-2026-109618, CVSS 9.2 / CVE-2026-109619,
CVSS 9.2). It affects the PHP runtime itself, not application code — all PHP
versions from 5.4 through 8.5.11 are vulnerable. Patched versions are:
8.5.12, 8.4.27, 8.3.36, 8.2.35. PHP 8.1 and older have no patch (EOL) and
must be upgraded to a supported branch.

Project context:
- Project name: [PROJECT NAME]
- Repo root: [PATH, if not current directory]
- Known deploy target(s): [e.g. single VPS / multiple client VPSes /
  Kubernetes / managed hosting — fill in what you know, or leave blank
  and have the agent determine it]
- Known build/deploy method, if you already know it: [e.g. Docker Compose,
  CI/CD pipeline, manual SSH deploy, Forge/Envoyer, Watchtower — or leave
  blank for the agent to find]

PHASE 1 — INVESTIGATE (do not change anything yet)

1. PHP runtime inventory
   - Find every Dockerfile in the repo and list the base image + tag each
     one uses. Note whether each tag is floating (e.g. `php:8.3-fpm`) or
     pinned to an exact version (e.g. `php:8.3.36-fpm`). Floating tags may
     already be patched upstream even if a stale local/CI build cache is
     serving an old layer — pinned tags are not patched until the pin is
     bumped.
   - If PHP is installed on the host directly (not just in containers),
     find the version management approach (apt/yum package, PPA, phpenv,
     asdf, manual build) and its current version.
   - List every docker-compose*.yml (and any Kubernetes manifests, Helm
     charts, or similar) and the image/tag each PHP-related service
     references.
   - Flag any other floating/unpinned base images or dependency versions
     in the same files — this class of bug (stale cached layer silently
     shipping an old version) is not PHP-specific.

2. Build pipeline
   - Is there CI/CD config (GitHub Actions, GitLab CI, Bitbucket Pipelines,
     Jenkins, etc.)? Where does it build the image(s), and does it use any
     layer caching (cache-from/cache-to, buildx cache, registry cache,
     Docker layer caching) that could reuse an old PHP base layer instead
     of pulling fresh on the next build?
   - Where do built images get pushed (registry, tag scheme — SHA, semver,
     branch name, `latest`)?

3. Versioning / release scheme
   - How are releases currently tagged/versioned (git tags, CHANGELOG,
     composer.json/package.json version field)?
   - Is there an existing "cut a release" process (script, Makefile
     target, tag-triggered CI job)?

4. Deployment / delivery
   - How does a built image or build artifact actually reach production
     or client servers — compose pull+up, a deploy script, webhook,
     manual SSH, Watchtower, Portainer, Forge, Envoyer, something else?
   - Is this multi-tenant / multi-client (separate servers per client
     each running their own instance), or a shared registry/tag that
     everyone pulls from? If multi-tenant, list every known deployment
     target you can find evidence of in the repo (deploy configs,
     inventory files, environment configs) so none get missed.

5. Build artifacts beyond the PHP binary
   - Does the build compile/bundle frontend assets (Vite, Webpack, Laravel
     Mix/Vite, esbuild) or run other build steps that need to be included
     in a fresh build, so the image doesn't "look" rebuilt while still
     shipping stale app code alongside the new PHP runtime?
   - Any vendored/bundled PHP binaries outside the normal package manager
     or Docker base image (e.g. a bundled php-cgi.exe, a hosting panel's
     own PHP, a serverless/Lambda layer) that also need checking?

After investigating, DO NOT make any changes. Report back with:
- A version inventory table: every PHP runtime found (host + each
  container/service), its current version, and whether it's
  vulnerable/patched/EOL.
- The exact sequence of commands (or CI trigger) needed to produce a
  genuinely fresh, patched build from source through to a deployed
  container/service — accounting for any caching found in step 2.
- A recommendation on pinning any floating base image tags found in
  step 1 to an explicit patched version, so this kind of silent-drift
  gap can't recur — but do not apply it yet.
- Any other floating/unpinned dependencies found along the way that pose
  the same silent-drift risk, for awareness (not necessarily in scope to
  fix now).
- If multi-tenant: a checklist of every deployment target that needs the
  fix applied, so none are missed.

Keep the report concise and actionable. I will review and tell you which
parts to execute.

PHASE 2 — APPLY (only after I confirm)

Once I've reviewed Phase 1 and told you to proceed, fix EVERY vulnerable
target found — both containerized/build-pipeline PHP AND any host-level
(system-installed) PHP — not just the Docker image.

2A. Containerized / image-based PHP (if applicable)
   1. Make the exact changes needed (pin/update base image version, bump
      package versions, update CI config if caching needs bypassing) —
      nothing beyond what I approved.
   2. Give me the exact commands to build, verify (confirm the new PHP
      version inside the built artifact before deploying), and
      deploy/push to each target identified in Phase 1.

2B. Host-level / system-installed PHP (if applicable)
   For each vulnerable host found in Phase 1, give me the exact commands
   for that host's actual package manager and distro — don't assume
   apt/Ubuntu if the investigation found something else (yum/dnf on
   RHEL/AlmaLinux, apk on Alpine, a cPanel/Plesk-managed PHP, a manually
   built binary, etc.). For an apt-based host specifically, the sequence
   is:
   - Check whether the distro's own repos already carry the patched
     version (`apt-cache policy phpX.Y-fpm`). If not, the OS repos lag
     upstream and a vendor repo is needed — on Ubuntu/Debian that's
     Ondřej Surý's PPA/repo (`ppa:ondrej/php`), added only if not already
     present.
   - Upgrade ONLY the version-suffixed packages (e.g. `php8.3-fpm`,
     `php8.3-cli`, `php8.3-common`, and every other installed `php8.3-*`
     extension package) — never the unversioned meta-packages
     (`php-fpm`, `php-cli`, `php`, etc.), since those can silently pull
     in a newer major/minor branch (e.g. jump 8.3 → 8.4) as a side
     effect of a security patch, which risks breaking app compatibility
     outside this fix's scope.
   - If a dpkg config-file prompt appears for something like
     `php-fpm.conf` or `www.conf` during the upgrade, the correct default
     is to KEEP the existing/local version (N/O), not the maintainer's
     version — tell me explicitly if this prompt appears and confirm you
     kept the local config, since overwriting it risks breaking the
     running pool/socket configuration.
   - Restart the correct service for the exact version upgraded (e.g.
     `systemctl restart php8.3-fpm`), not a generic `php-fpm` service
     name if the install is version-suffixed.
   - Verify the fix landed in BOTH the CLI binary and the actual running
     FPM pool, not just one:
     - `phpX.Y -v` (or `php -v` if that's what `update-alternatives`
       points at) to confirm the binary itself.
     - A live check against the actual running service — e.g.
       `systemctl status phpX.Y-fpm`, and if there's a way to check the
       application's live response (such as an HTTP header the app
       exposes, or hitting a known endpoint through the real vhost/SNI,
       not just the bare IP), use that to confirm the patch is serving
       real traffic, not just installed on disk.
   - If anything errors or the service fails to come back up after the
     restart, STOP and report the exact error — do not attempt further
     changes without my input, since a broken PHP-FPM pool takes the
     site offline.

3. After all fixes (2A and 2B) are applied, give me ONE combined
   verification step per target — host(s) and container(s) alike — I can
   run myself to independently confirm every target is patched (e.g. a
   version-check command per target, or re-running an existing scan
   script if one exists in this conversation/repo).

Do not skip Phase 1 and jump to changes. Do not assume a single deploy
target if the investigation suggests multiple. Do not assume the fix is
only needed in Docker — apply it everywhere Phase 1 found a vulnerable
PHP runtime, host included. Do not apply the pinning recommendation
without my explicit go-ahead.
```

---

## Why it's structured this way

- **Investigate-before-acting** stops an agent from guessing at an unfamiliar
  pipeline and pushing a change that breaks a live deploy.
- Explicitly asks about **build caching**, which is the exact failure mode
  that causes a floating tag to silently keep serving an old, vulnerable
  layer.
- Separates **"what do I run right now to ship the fix"** from **"should we
  pin versions going forward"** — the second is a policy decision, not an
  emergency-patch decision, so it shouldn't get bundled in under pressure.
- Explicitly handles the **multi-tenant case**, so a fix doesn't quietly land
  on one client's server while others stay vulnerable.
- Phase 2 only runs on your explicit confirmation, and it closes the loop
  with a **live verification step** — confirming the build succeeded isn't
  the same as confirming production is actually serving the patched version.