package tty

import (
	"os"
	"testing"
)

func TestDevNullIsNotATerminal(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if Is(f) {
		t.Fatal("/dev/null reported as a terminal")
	}
}
