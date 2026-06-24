package main

import (
	"errors"
	"testing"

	"github.com/shinagawa-web/tinytap/internal/loader"
)

func TestLoadBPF_Error(t *testing.T) {
	orig := loaderLoad
	defer func() { loaderLoad = orig }()
	want := errors.New("load fail")
	loaderLoad = func(uint32) (*loader.Tinytap, error) { return nil, want }

	_, err := loadBPF(0)
	if err != want {
		t.Errorf("got %v, want %v", err, want)
	}
}

func TestLoadBPF_Success(t *testing.T) {
	orig := loaderLoad
	defer func() { loaderLoad = orig }()
	loaderLoad = func(uint32) (*loader.Tinytap, error) { return &loader.Tinytap{}, nil }

	sess, err := loadBPF(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess == nil {
		t.Error("want non-nil session")
	}
}
