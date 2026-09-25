FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:a6a7b6569fb3dfde907aafcbdd31fbb9e6004def002b108cca7bfaafd39e1a91

COPY . $SRC/tinytap
WORKDIR $SRC/tinytap
COPY .clusterfuzzlite/build.sh $SRC/
