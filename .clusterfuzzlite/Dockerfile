FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:752250ed44cd0d770d1c71dc12925c50dff454db2ea7bc019f43782cbd610de2

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
