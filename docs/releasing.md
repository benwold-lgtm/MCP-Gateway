# Releasing

Maintainer checklist. It exists because the steps split either side of the tag, and the ones
that come *after* it are the ones that get forgotten — the digest pins cannot be written until
the tag has built the image that produced them.

For upgrading an existing deployment, see [upgrade.md](upgrade.md); this document is about
cutting the release, not consuming it.

> **Run this checklist, do not read it.** The first time it was followed end to end, one of its
> own commands turned out not to exist. A checklist you only read is a checklist that rots.

## 1. Before the tag

1. **Settle the content.** Everything in the release should be merged to `main` with CI green.
   Check the [Actions status page](https://www.githubstatus.com/) if runs are missing — a
   throttled webhook looks exactly like a workflow that was never meant to fire.
2. **Distinguish a real red from an infrastructure red.** Jobs `cancelled` with **zero steps
   executed** were never scheduled. A `failure` in `Initialize containers` is the Redis service
   container, not your code — the same commit passing on its `pull_request` run while failing
   on its `push` run is the tell. Compare runs on the *same SHA* before believing either.
3. **Close the changelog section.** Rename `## [Unreleased]` to `## [<version>] - <date>`,
   leave a fresh empty `## [Unreleased]` above it, and add the link reference at the bottom.
   Lead with what an upgrader must read **before** upgrading — breaking gates, changed request
   handling — not with the feature list. Check you have not left two `### Security` headings in
   one section.
4. **Bump `pyproject.toml`.** That is the only place the version lives; `__version__` reads it
   from installed package metadata and `/health` reports that, so nothing else needs editing.
5. **Pick the number honestly.** A new capability is a minor bump even at `0.x`, and this
   project ships breaking changes in minor releases by policy — say so in the notes rather than
   reaching for a patch number to make an upgrade feel smaller than it is.
6. **Consider a dependency refresh.** `pip-compile --upgrade` often clears most of what
   `pip-audit` is reporting with no constraint changes at all, and a release artifact is the
   right place to spend that. Verify it in a **clean** virtualenv and re-check the guards named
   in [dependency-advisories.md](dependency-advisories.md).
7. **Merge the release-prep PR.** The tag goes on `main`, not on the branch.

## 2. The tag

```bash
git checkout main
git log --oneline -1              # confirm you are on the merge commit
git status --short                # expect no output
grep '^version' pyproject.toml    # expect the version you are about to tag

git tag -a v<version> -m "v<version> — <one-line summary>"
git push origin v<version>
```

If `origin` is an SSH remote whose key is not registered on the account, **every** networked
git command fails, `fetch` included — so a stale `origin/main` will claim you are "ahead by N
commits" when you are not. Confirm against the remote without SSH:

```bash
git ls-remote https://github.com/benwold-lgtm/MCP-Gateway.git refs/heads/main
```

and push over HTTPS instead. Never write a token into the remote URL — use a credential helper
for the single command.

`release-image.yml` triggers on `v*` and publishes to GHCR. It also carries a
`workflow_dispatch`, so if the push does not schedule a run the release can still be built from
the Actions tab **without moving the tag**.

**Do not tag while Actions is unhealthy.** A partial run leaves a tag with no images behind it,
and the fix is a manual re-run that needs `actions: write`.

## 3. Verify the artifact

Do this *before* re-pinning anything — the pin is only worth writing if the image behind it is
good.

The CLI has **no `--version` flag**; the version comes from installed package metadata:

```bash
docker run --rm --entrypoint python \
  ghcr.io/benwold-lgtm/device-mcp-gateway:<version> \
  -c "from device_mcp_gateway import __version__; print(__version__)"
```

Confirm the GHCR package is pullable **without credentials**. A private package fails with an
authentication error that never mentions visibility, so this is worth a deliberate check rather
than discovering it through a user:

```bash
docker logout ghcr.io
docker manifest inspect ghcr.io/benwold-lgtm/device-mcp-gateway:<version>
```

## 4. After the tag — the part that gets forgotten

The digest does not exist until the release build finishes, so none of this can be done in the
prep PR. It is a second, small PR.

1. **Read the digest.** Take the **index** digest, not a per-platform one — the index is what
   resolves for both amd64 and arm64:
   ```bash
   docker buildx imagetools inspect ghcr.io/benwold-lgtm/device-mcp-gateway:<version>
   ```
2. **Re-pin every reference, together**, tag and digest moving as one. A manifest carrying a new
   tag beside an old digest deploys the old image while claiming the new one:
   - `deploy/kubernetes/deployment.yaml`
   - `deploy/kubernetes/worker-deployment.yaml`
   - the commented example in `deploy/kubernetes/kustomization.yaml`
   - the image references in `README.md` and `docs/kubernetes-architecture.md`
3. **Confirm gateway and worker carry the identical reference.** The worker runs the *gateway*
   image with a different command; they share the Redis data model, so a skew across a schema
   change is a split-brain risk:
   ```bash
   grep -h 'image: ghcr.io' deploy/kubernetes/{deployment,worker-deployment}.yaml | sort -u | wc -l   # expect 1
   ```
4. **Check the pinned digest actually resolves**, so a typo cannot ship:
   ```bash
   docker manifest inspect ghcr.io/benwold-lgtm/device-mcp-gateway:<version>@sha256:<digest>
   ```
5. **Run the manifest tests:** `pytest tests/test_deploy_manifests.py tests/test_k8s_manifests.py`
6. **Publish the GitHub Release** with the changelog section as its body.

## 5. Close the loop

Confirm `/health` reports the new version from a deployment running the **new digest**. That is
the only check that spans `pyproject.toml` → image → running process; everything above verifies
one link of that chain in isolation.
