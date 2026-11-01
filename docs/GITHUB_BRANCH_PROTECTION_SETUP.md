# Protect the FUTUREVERSE main branch

The repository needs branch protection/rulesets enabled by a repository administrator. This document is a setup checklist; it does not itself change repository settings.

## Recommended GitHub ruleset

In GitHub: **Settings → Rules → Rulesets → New branch ruleset**.

- Name: protect-main
- Enforcement: Active
- Target: default branch main
- Restrict deletions: enabled
- Block force pushes: enabled
- Require a pull request before merging: enabled
- Required approvals: 1 where a second reviewer is available
- Dismiss stale approvals when new commits are pushed: enabled
- Require conversation resolution: enabled
- Require status checks: enable after the workflow has produced its first successful run; select security-primitives
- Require branches to be up to date before merging: enabled after CI is stable
- Include administrators: enabled, if repository settings allow it

Do not make a required check mandatory until it has appeared at least once on a PR. Otherwise the branch can become impossible to merge until the check name is corrected.

## CI introduced by this PR

.github/workflows/security-primitives.yml runs on pull requests to main and pushes to security/**. It tests only the isolated adaptive-security and owner-cookie CSRF primitives. It is not the full application build or end-to-end suite.

The workflow:
- requests only contents: read;
- uses SHA-pinned GitHub Actions;
- disables persisted checkout credentials;
- uses no repository secrets;
- installs an exact, isolated TypeScript transpiler version;
- runs the adaptive-layer and CSRF regression tests.

## After enabling the ruleset

1. Open a small test PR and confirm the security-primitives job is reported.
2. Enable it as a required status check.
3. Confirm merge is blocked when the job fails.
4. Keep production deployment on a separate, manually approved workflow.
