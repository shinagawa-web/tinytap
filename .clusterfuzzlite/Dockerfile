FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:6ce6d73ddfca539db4447a0ef115f2b222be8b7532e8d512271b1685587ab057

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
