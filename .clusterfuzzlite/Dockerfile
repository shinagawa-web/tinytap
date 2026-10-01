FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:95203d2b95d85f24f5e22ac3e144dc81aff49249f253dbe8eed40df70dbb1bbc

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
