//go:build unix

// Package tty tells whether a file is a real terminal (not just a character
// device such as /dev/null).
package tty

import (
	"os"
	"syscall"
	"unsafe"
)

// Is reports whether f is a terminal.
func Is(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), ioctlGetTermios, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
