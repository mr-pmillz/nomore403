//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package cli

import "os"

func openValidatedPrivateHeaderFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errPrivateHeaderFileInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errPrivateHeaderFileInvalid
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errPrivateHeaderFileInvalid
	}
	return file, nil
}
