# Build image for scripts/sandbox_build.py (plan B2, docs/plans/2026-10-27-sicherheitskette/PLAN-B2-build.md
# approach 1): the pinned python-test image plus the Codex CLI. The Codex build, its isolation probe
# and nothing else run in it; the injecting proxy runs in python-test.
#
# A HUMAN builds this image (it needs the network) and records the resulting id in
# config/sandbox-policy.json (`images.codex-build`) in a reviewed commit; the runner itself never
# pulls or builds (`--pull=never`, the image id must match).
#
# The base is the LOCAL tag claudex-sandbox-python-test:3. A tag is not a pin, so check first that
# it carries the id the policy pins for `images.python-test`, and build only if it does:
#
#   docker --context desktop-linux image inspect --format '{{.Id}}' claudex-sandbox-python-test:3
#   docker --context desktop-linux build -f config/sandbox/codex-build.Dockerfile \
#     -t claudex-sandbox-codex-build:1 config/sandbox
#   docker --context desktop-linux image inspect --format '{{.Id}}' claudex-sandbox-codex-build:1
#
# Codex: the npm tarball @openai/codex@0.162.1-linux-x64 (measured 2026-11-01: 165 453 522 bytes,
# sha256 below, npm integrity sha512-cjK2mdHIfEepZ1lQ1MX3aTQC+8ncIsvnacl/6vI2dIIcfP8/MrhTQ2+qRlkXFNDzJSj1d36quIszP+3/4CUJWQ==).
# It contains a static musl binary under package/vendor/x86_64-unknown-linux-musl/. ADD checks the
# sha256 before the bytes are used; a remote ADD does not unpack, so a separate stage unpacks it and
# only the unpacked tree reaches the final image. Bump version, URL, checksum and the policy's
# `codex_version` together.

FROM claudex-sandbox-python-test:3 AS fetch
ADD --checksum=sha256:7417711678b464eee70664126e39e88bb3c84c2928da0e71f14b56e04ff5c09f \
    https://registry.npmjs.org/@openai/codex/-/codex-0.162.1-linux-x64.tgz /fetch/codex.tgz
RUN mkdir -p /opt/codex \
 && tar -xzf /fetch/codex.tgz -C /opt/codex --no-same-owner --no-same-permissions \
 && chmod -R a+rX,go-w /opt/codex \
 && test -x /opt/codex/package/vendor/x86_64-unknown-linux-musl/bin/codex

FROM claudex-sandbox-python-test:3
COPY --from=fetch /opt/codex /opt/codex
# `codex` on PATH, and the tarball's own helper directory (rg) after it, as the npm launcher does.
ENV PATH=/opt/codex/package/vendor/x86_64-unknown-linux-musl/bin:/opt/codex/package/vendor/x86_64-unknown-linux-musl/codex-path:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# CODEX_HOME must exist and be writable by uid 65532 before the first Codex call (measured
# 2026-11-01: even `codex --version` writes $CODEX_HOME/tmp/arg0/). At run time the runner mounts a
# tmpfs here (policy `build.codex_home_tmpfs`) and the driver writes the placeholder auth.json and
# the per-run CA into it; the directory below is only the mount point and the default.
RUN mkdir -p /codex-home \
 && chown 65532:65532 /codex-home \
 && chmod 0700 /codex-home \
 && mkdir /tmp/codex-check \
 && CODEX_HOME=/tmp/codex-check codex --version | grep -qx 'codex-cli 0.162.1' \
 && rm -rf /tmp/codex-check
ENV CODEX_HOME=/codex-home

# As in python-test: nothing here runs at start-up; the entry point is the plugin's driver.
