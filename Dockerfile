# Minimal, non-root scan-runner image. This is the trust boundary for an
# audience handling someone else's confidential deal data on day one --
# distroless (no shell, no package manager) and read-only-root-fs compatible
# by design, not as an afterthought.

FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt
# `pip install --target=` bakes the *builder* image's interpreter path into
# each console-script's shebang (e.g. #!/usr/local/bin/python3). That path
# doesn't exist in the distroless runtime image below, which breaks not
# just running these scripts directly but also semgrep's compiled core,
# which internally execvp()s the literal command "pysemgrep" off PATH --
# found by actually running the built image, not by inspecting the
# Dockerfile. Rewriting the shebang to the runtime image's real
# interpreter path fixes both.
RUN sed -i '1s|^#!.*|#!/usr/bin/python|' /deps/bin/semgrep /deps/bin/pysemgrep

FROM gcr.io/distroless/python3-debian12:nonroot AS runtime

ENV PYTHONPATH=/deps \
    PATH="/deps/bin:${PATH}" \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    HOME=/tmp

WORKDIR /app
COPY --from=builder /deps /deps
COPY main.py .
# findings.py and finding_adapters.py: every scanner module now imports
# these unconditionally at module load time (the normalized-finding layer),
# so main.py's own import chain fails without them even though main.py
# never imports them directly -- confirmed by tracing the actual runtime
# import graph from main.py, not by inspecting source. harvestguard.py and
# reports.py are the CLI's own entry points; traced and confirmed neither is
# reachable from main.py's import graph, so they're deliberately not copied
# here -- this image only ever runs the Streamlit entrypoint.
COPY findings.py .
COPY finding_adapters.py .
COPY scanner/ scanner/
COPY analyzer/ analyzer/
COPY classifier/ classifier/
COPY code_analysis/ code_analysis/
COPY dashboard/ dashboard/

# Base image's :nonroot tag already runs as uid/gid 65532; no USER directive
# needed. /tmp is the only writable path required at runtime (Streamlit's
# runtime cache, and -- found by actually running the built image under
# --read-only, not by inspecting the Dockerfile -- semgrep's own settings
# file, which it tries to write to $HOME/.semgrep; HOME is pointed at /tmp
# above specifically so that write lands somewhere writable). Mount /tmp as
# a tmpfs when running with --read-only:
#   docker run --read-only --tmpfs /tmp ...
EXPOSE 8501

# --global.developmentMode=false is required: Streamlit auto-detects dev
# mode based on how it's installed, `pip install --target=` reads as a dev
# install, and dev mode serves the frontend from a separate process on
# port 3000 instead of the backend port -- found by actually running the
# built image, not by inspecting the Dockerfile.
ENTRYPOINT ["python", "-m", "streamlit", "run", "main.py", \
            "--server.address=0.0.0.0", "--server.headless=true", \
            "--global.developmentMode=false"]
