FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:5a43cfd13e3b7602eaba5825f93f291d5384c08cc55b05ab6e4e6b948e229cb7

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
