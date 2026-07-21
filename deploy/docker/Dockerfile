# ZERO-WINDOW service image.
#
# One image for all services; the entrypoint selects which CLI runs. Building
# once means the authority and every centre run bit-identical code, which
# matters because paper generation must be byte-reproducible across hosts.
#
# Pinned to the Node 20 LTS line: the runtime is part of the reproducibility
# surface, so it is pinned by digest in deploy/compose rather than floating.
FROM node:20.18.1-bookworm-slim AS build

# build-essential + python3: sodium-native, better-sqlite3 and pkcs11js are
# native modules and are compiled here rather than pulled as prebuilt binaries.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
# The corepack bundled with the Node image ships signing keys that have since
# rotated, so `corepack prepare` fails signature verification against the
# current npm registry ("Cannot find matching keyid"). Updating corepack first
# picks up the current keys. Pinned so the build stays reproducible.
RUN npm install --global corepack@0.34.0 \
 && corepack enable \
 && corepack prepare pnpm@9.15.9 --activate

WORKDIR /src
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml tsconfig.base.json vitest.shared.ts ./
COPY packages ./packages
RUN pnpm install --frozen-lockfile --prefer-offline
RUN pnpm build
# Drop dev dependencies from the tree that ships. `pnpm deploy` is not used
# here: in a workspace it requires inject-workspace-packages, and its
# --legacy escape hatch was removed in pnpm 9. Pruning the built workspace in
# place is simpler and keeps the layout identical to a source checkout, which
# matters because paper rendering must be byte-reproducible across hosts.
RUN pnpm -r exec rm -rf src test && pnpm prune --prod

FROM node:20.18.1-bookworm-slim AS runtime

# libsofthsm2: the PKCS#11 provider used when ZW_KEY_PROVIDER=pkcs11 without
# dedicated hardware. Real HSM deployments mount the vendor module instead
# (see INTEGRATIONS.md).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates softhsm2 tini \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged: nothing here needs root, and the state directory is the only
# writable path.
RUN groupadd --system --gid 10001 zerowindow \
 && useradd --system --uid 10001 --gid zerowindow --home /var/lib/zero-window zerowindow \
 && mkdir -p /var/lib/zero-window \
 && chown -R zerowindow:zerowindow /var/lib/zero-window

COPY --from=build /src /opt/zero-window
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER zerowindow
WORKDIR /var/lib/zero-window
ENV NODE_ENV=production ZW_STATE_DIR=/var/lib/zero-window

# tini reaps zombies and forwards SIGTERM, so graceful shutdown actually runs.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["help"]
