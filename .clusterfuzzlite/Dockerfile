FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:47967ced96d431dfe3488e42c44a545c5c32365e38517e5becdc99ac5c307670

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
