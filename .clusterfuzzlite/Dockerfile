FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:2d8d85db85039b0d2d5f62d170bc6fe8a465c6aa438cc1bee0465c96017f4d01

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
