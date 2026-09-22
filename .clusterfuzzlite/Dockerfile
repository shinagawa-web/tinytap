FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:68d51737a25f21ead9fe46292db205694d9000c369aa1f380c73d4e8647924a5

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
