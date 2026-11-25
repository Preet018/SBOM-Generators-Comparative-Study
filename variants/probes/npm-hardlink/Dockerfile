# Controlled probe for the Ghost (pnpm) finding: two npm packages that differ ONLY in how their package.json is
# stored in the image layer. pnpm hard-links package files out of its content-addressed store; when the store
# sorts first, the layer tar holds the store copy as the regular file and the package's package.json as a
# HARD-LINK entry pointing at it.
#   docker build -t p16/npm-hardlink-probe variants/probes/npm-hardlink && docker save -o probe.tar p16/npm-hardlink-probe
# Result (syft 1.57.2 / trivy 0.76.2 / cdxgen 13.2.0): regular-pkg found by all three; linked-pkg found by Syft only.
FROM alpine:3.22
RUN mkdir -p /app/node_modules/regular-pkg /app/node_modules/linked-pkg /a-store \
 && printf '{"name":"regular-pkg","version":"1.0.0"}\n' > /app/node_modules/regular-pkg/package.json \
 && printf '{"name":"linked-pkg","version":"2.0.0"}\n' > /a-store/linked-pkg.json \
 && ln /a-store/linked-pkg.json /app/node_modules/linked-pkg/package.json
