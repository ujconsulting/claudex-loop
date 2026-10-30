# Test image for scripts/sandbox_run.py (plan B1, docs/plans/2026-10-27-sicherheitskette/PLAN-B1-sandbox-run.md).
#
# A HUMAN builds this image (it needs the network) and records the resulting digest in
# config/sandbox-policy.json in a reviewed commit; the runner itself never pulls or builds
# (`--pull=never`, the image id must match). Everything a run needs is inside: no dependency is
# fetched at run time (B1 supports only image-contained dependencies; B1.5 is the rest).
#
#   docker --context desktop-linux build -f config/sandbox/python-test.Dockerfile \
#     -t claudex-sandbox-python-test:2 config/sandbox
#   docker --context desktop-linux image inspect --format '{{.Id}}' claudex-sandbox-python-test:2
#
# Base pinned by digest (python:3.13-slim, pulled 2026-10-30). pytest and its dependencies are
# installed with --require-hashes from the pinned set below (wheels only). git comes from the
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
