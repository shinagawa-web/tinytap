FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:a6f78ea274618aef8ce3895b7464d6c65fb2b8c3e8c036c2f0974e062be63a67

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
