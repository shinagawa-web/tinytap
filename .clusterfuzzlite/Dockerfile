FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:1b17a449039e08305950e3bd4cdc5ccab843d5e70586f96a34214e68a98db9a0

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
