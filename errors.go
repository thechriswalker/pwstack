package stack

import "errors"

var (
	// ErrDeprecatedHash is returned from stack.Compare when the password matches, but should be upgraded
	ErrDeprecatedHash = errors.New("deprecated Hash")

	ErrInvalidHash = errors.New("hash is badly formed")

	ErrUnknownVersion = errors.New("hash version is unknown")

	errNilHasher = errors.New("cannot use a nil Hasher in the stack")
)
