FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:d6662fd3bd0eb72e535934c8e99448dbb4f8cce94f356eaea9e1e08e33f2c9b4

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
