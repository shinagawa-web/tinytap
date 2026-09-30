FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:326aa2055a7a6e78812c078ddee5dfe1710b09e1c0bb6b062565aa7c9661e009

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
