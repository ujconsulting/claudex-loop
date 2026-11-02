# Test image for scripts/sandbox_run.py (plan B1, docs/plans/2026-10-27-sicherheitskette/PLAN-B1-sandbox-run.md).
#
# A HUMAN builds this image (it needs the network) and records the resulting digest in
# config/sandbox-policy.json in a reviewed commit; the runner itself never pulls or builds
# (`--pull=never`, the image id must match). The image fetches nothing at run time and has no
# network. Dependencies beyond what is inside are handed in by the runner (B1.5, `--deps`): wheels
# selected by hash and verified on the host, installed offline by pip inside the container.
#
# Tag :3 (plan B2, PLAN-B2-build.md approach 1): adds `cryptography` (+ cffi, pycparser) for the
# injecting proxy of the Codex build, which runs in this image; it is also the base of
# config/sandbox/codex-build.Dockerfile. Rebuilding changes B1's pinned id and B1.5's image closure.
#
#   docker --context desktop-linux build -f config/sandbox/python-test.Dockerfile \
#     -t claudex-sandbox-python-test:3 config/sandbox
#   docker --context desktop-linux image inspect --format '{{.Id}}' claudex-sandbox-python-test:3
#
# Base pinned by digest (python:3.13-slim, pulled 2026-10-30). pytest, cryptography and their
# dependencies are installed with --require-hashes from the pinned set (wheels only). git comes from the
# Debian archive of the base image and is NOT hash-pinned: the resulting image digest is what
# pins it, and that digest is what the runner checks.
FROM python@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

COPY requirements-test.txt /opt/claudex/requirements-test.txt
RUN python3 -m pip install --no-cache-dir --only-binary=:all: --require-hashes \
      -r /opt/claudex/requirements-test.txt \
 && git config --system safe.directory '*'

# The runner starts the container as uid 0 with only SETUID/SETGID/KILL; the command itself runs
# as 65532. Nothing here runs at start-up: the entry point is the plugin's driver, passed by the
# runner as `python3 -I -S -c <source>`.
