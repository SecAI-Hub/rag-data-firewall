package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// writerLock coordinates cooperating processes on a local Linux filesystem.
// Keep the empty lock file after close: unlinking would let another opener lock
// a new inode while an existing process still owns the original lock.
// Callers serialize Validate and Close with their store/audit mutex.
type writerLock struct {
	path string
	file *os.File
	dir  os.FileInfo
}

func acquireWriterLock(path string) (*writerLock, error) {
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("writer lock requires a private directory")
	}
	// #nosec G304 -- operator-selected private state path; no-follow open and
	// inode, owner, mode, size and link checks follow before any state is read.
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open writer lock: %w", err)
	}
	lock := &writerLock{path: path, file: file, dir: dir}
	ok := false
	defer func() {
		if !ok {
			_ = lock.Close()
		}
	}()
	if err := lock.Validate(); err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("another process owns the writer lock: %w", err)
	}
	if err := lock.Validate(); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := syncPrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	ok = true
	return lock, nil
}

func (lock *writerLock) Validate() error {
	if lock == nil || lock.file == nil {
		return fmt.Errorf("writer lock is closed")
	}
	dir, err := os.Lstat(filepath.Dir(lock.path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 || !os.SameFile(dir, lock.dir) {
		return fmt.Errorf("writer directory changed")
	}
	pathInfo, err := os.Lstat(lock.path)
	if err != nil {
		return fmt.Errorf("writer lock path unavailable: %w", err)
	}
	info, err := lock.file.Stat()
	if err != nil || !pathInfo.Mode().IsRegular() || !info.Mode().IsRegular() ||
		pathInfo.Mode().Perm()&0077 != 0 || info.Mode().Perm()&0077 != 0 ||
		pathInfo.Size() != 0 || info.Size() != 0 || !hasSingleLink(pathInfo) || !hasSingleLink(info) ||
		!os.SameFile(info, pathInfo) {
		return fmt.Errorf("writer lock must remain an empty private single-link file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("writer lock must be owned by the service user")
	}
	return nil
}

func (lock *writerLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := lock.file.Close()
	lock.file = nil
	return err
}

func syncPrivateDirectory(path string) error {
	// #nosec G304 -- only called with the verified private storage directory.
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
