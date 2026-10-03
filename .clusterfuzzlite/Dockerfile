FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:97cda6777e802c20b9a055dcaa20a844ab172edc40554eaa8a8384a1c5c238cb

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
