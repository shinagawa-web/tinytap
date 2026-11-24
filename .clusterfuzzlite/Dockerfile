FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:68eb389f79e1b58277412ef425fab4c412cd4f61c521ce355a49c8cdd1a33e1e

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
