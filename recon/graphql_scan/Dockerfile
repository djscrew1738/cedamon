# RedAmon graphql-cop sidecar
# ======================================================================
# Builds graphql-cop from upstream source (tag 1.16) so the -e exclusion
# flag is honored. The official DockerHub image is stuck at 1.14, which
# ignores -e and always runs all 12 tests. This custom image lets us skip
# DoS-class probes at the traffic level (e.g. in stealth mode) while still
# running the low-traffic info-leak / CSRF checks.
# ======================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Team"
LABEL description="graphql-cop 1.16 sidecar with -e exclusion support"
LABEL upstream="https://github.com/dolevf/graphql-cop"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pin upstream tag. 1.16 adds -e support and keeps the 12 canonical tests
# (field_duplication is commented out upstream).
ARG GRAPHQL_COP_VERSION=1.16

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git \
    && rm -rf /var/lib/apt/lists/* && apt-get clean

WORKDIR /opt/graphql-cop
RUN git clone --depth 1 --branch "${GRAPHQL_COP_VERSION}" \
        https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "graphql-cop.py"]
