//go:build aix || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package cli

import (
	"os"

	"golang.org/x/sys/unix"
)

func openValidatedPrivateHeaderFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errPrivateHeaderFileInvalid
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errPrivateHeaderFileInvalid
	}
	file := os.NewFile(uintptr(fd), "private-header-file")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errPrivateHeaderFileInvalid
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		int64(stat.Uid) != int64(os.Geteuid()) || stat.Mode&0o077 != 0 {
		_ = file.Close()
		return nil, errPrivateHeaderFileInvalid
	}
	return file, nil
}
