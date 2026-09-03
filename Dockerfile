FROM alpine:3.24.1

ARG TARGETPLATFORM

# nomore403 embeds every payload wordlist in the binary, so no payload volume is
# needed. curl is a real runtime dependency: the http-versions, http-parser and
# absolute-uri techniques shell out to it for request forms net/http normalizes
# away. tini reaps zombies and forwards signals.
RUN apk add --no-cache ca-certificates curl tini \
    && addgroup -S -g 65532 nomore403 \
    && adduser -S -D -H -u 65532 -G nomore403 nomore403

COPY $TARGETPLATFORM/nomore403 /usr/local/bin/nomore403
RUN chmod 0755 /usr/local/bin/nomore403

USER 65532:65532
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/nomore403"]
