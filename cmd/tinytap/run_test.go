package main

import (
	"errors"
	"testing"
)

func TestCloseSink_NoError(t *testing.T) {
	closeSink(&fakeSink{})
}

func TestCloseSink_WithError(t *testing.T) {
	closeSink(&fakeSink{closeErr: errors.New("close failed")})
}
