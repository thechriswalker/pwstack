package stack

import "errors"

var (
	// ErrDeprecatedHash is returned from stack.Compare when the password matches, but should be upgraded
	ErrDeprecatedHash = errors.New("deprecated Hash")

	ErrInvalidHash = errors.New("hash is badly formed")

	ErrUnknownVersion = errors.New("hash version is unknown")

	errNilScheme        = errors.New("cannot use a nil password scheme in the stack")
	errDuplicateVersion = errors.New("duplicate scheme version in stack")
	errInvalidSalt      = errors.New("salt length invalid")
)
