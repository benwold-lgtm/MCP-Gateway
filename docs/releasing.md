# Releasing

Maintainer checklist. This exists because the steps split either side of the tag, and the
ones that come *after* it are the ones that get forgotten — the digest pins cannot be written
until the tag has built the image that produced them.

For upgrading an existing deployment, see [upgrade.md](upgrade.md); this document is about
cutting the release, not consuming it.

## Before the tag

1. **Settle the content.** Everything landing in the release should be merged to `main` with
   CI green. Check the [Actions status](https://www.githubstatus.com/) if runs are missing —
   a throttled webhook looks exactly like a workflow that was never meant to fire.
2. **Close the changelog section.** Rename `## [Unreleased]` to `## [<version>] - <date>`,
   leave a fresh empty `## [Unreleased]` above it, and add the link reference at the bottom.
   Lead with what an upgrader must read before upgrading — breaking gates and changed request
   handling — not with the feature list.
3. **Bump `pyproject.toml`.** That is the only place the version lives; `__version__` reads it
   from installed package metadata, and `/health` reports that, so nothing else needs editing.
4. **Pick the number honestly.** A new capability is a minor bump even at `0.x`, and this
   project ships breaking changes in minor releases by policy — say so in the notes rather
   than reaching for a patch number to make an upgrade feel smaller than it is.
5. **Merge the release-prep PR.** The tag goes on `main`, not on the branch.

## The tag

```bash
git tag -a v<version> -m "v<version> — <one-line summary>"
git push origin v<version>
```

`release-image.yml` triggers on `v*` and publishes to GHCR. It also carries a
`workflow_dispatch`, so if the push does not schedule a run — throttled webhooks, a degraded
Actions — the release can still be built from the Actions tab without moving the tag.

**Do not tag while Actions is unhealthy.** A partial run leaves a tag with no images behind
it, and the fix is a manual re-run that needs `actions: write`.

## After the tag — the part that gets forgotten

The image digest does not exist until the release build finishes, so these steps cannot be
done in the prep PR. They are a second, small PR.

1. **Read the digest** the build produced:
   ```bash
   docker buildx imagetools inspect ghcr.io/benwold-lgtm/device-mcp-gateway:<version>
   ```
2. **Re-pin every reference, together.** They must not disagree — a manifest carrying a new
   tag beside an old digest deploys the old image while claiming the new one:
   - `deploy/kubernetes/deployment.yaml`
   - `deploy/kubernetes/worker-deployment.yaml` (the worker runs the *gateway* image with a
     different command — same reference, deliberately)
   - the commented example in `deploy/kubernetes/kustomization.yaml`
   - the image references in `README.md` and `docs/kubernetes-architecture.md`
3. **Publish the GitHub Release** with the changelog section as its body.
4. **Check the GHCR packages are public** if this is the first release to add one — a new
   package defaults to private, and a private image fails a pull with an authentication error
   rather than anything that names the visibility.

## Verify

The CLI has **no `--version` flag** — the version is single-sourced from installed package
metadata, so read it from there:

```bash
docker run --rm --entrypoint python \
  ghcr.io/benwold-lgtm/device-mcp-gateway:<version> \
  -c "from device_mcp_gateway import __version__; print(__version__)"
```

Confirm the GHCR package is pullable without credentials, which is the failure an operator
would otherwise hit as an unhelpful authentication error:

```bash
docker logout ghcr.io
docker manifest inspect ghcr.io/benwold-lgtm/device-mcp-gateway:<version>
```

Then confirm `/health` reports the new version from a deployment running the new digest — that
closes the loop from `pyproject.toml` through the image to the running process.
