//go:build !cgo

package piv

import "errors"

// OpenCard is unavailable in builds without cgo: smart card access needs the
// platform PC/SC library. Build ykgpg natively (CGO_ENABLED=1) to log in.
func OpenCard(serial string) (Card, error) {
	return nil, errors.New("this ykgpg build has no smart card support (built without cgo); build from source on the machine that has the YubiKey")
}

// CardSerials is unavailable in builds without cgo.
func CardSerials() ([]string, error) {
	return nil, errors.New("this ykgpg build has no smart card support (built without cgo)")
}
