package stack

import (
	"fmt"
)

// Stack represents a password hashing system, which may support more than
// one method of password hashing over time.
type Stack struct {
	preferred uint8
	hashers   map[uint8]Hasher
}

// Hasher is the interface that all the password hashing
// schemes must implement.
// This package provides 2 implementations, scrypt and argon2
type Hasher interface {
	Hash(plaintext []byte) (hash []byte, err error)
	Compare(plaintext, hash []byte) (bool, error)
}

type Option interface {
	apply(s *Stack) error
}

type optionFn func(s *Stack) error

func (fn optionFn) apply(s *Stack) error {
	return fn(s)
}

func New(options ...Option) (*Stack, error) {

	s := &Stack{
		hashers: map[uint8]Hasher{},
	}
	for _, o := range options {
		if err := o.apply(s); err != nil {
			return nil, fmt.Errorf("error applying stack.Option: %w", err)
		}
	}
	if _, ok := s.hashers[s.preferred]; !ok {
		return nil, fmt.Errorf("must provide a preferred Hasher")
	}

	return s, nil
}

// WithDeprecated adds alternative legacy hashers to the stack.
// This means we will check the stored hashes against these hashers
// if the preferred hash fails.
func WithPreferred(version uint8, hasher Hasher) Option {
	return optionFn(func(s *Stack) error {
		// if there already is a preferred, then bail.
		if _, ok := s.hashers[s.preferred]; ok {
			return fmt.Errorf("attempt to register 2 preferred hashes")
		}
		if _, ok := s.hashers[version]; ok {
			return fmt.Errorf("attempt to register 2 hashes with the same version: %02x", version)
		}
		if hasher == nil {
			return errNilHasher
		}
		s.preferred = version
		s.hashers[version] = hasher
		return nil
	})
}

// WithDeprecated adds alternative legacy hashers to the stack.
// This means we will check the stored hashes against these hashers
// if the preferred hash fails.
func WithDeprecated(version uint8, hasher Hasher) Option {
	return optionFn(func(s *Stack) error {
		if _, ok := s.hashers[version]; ok {
			return fmt.Errorf("attempt to register 2 hashes with the same version: %02x", version)
		}
		if hasher == nil {
			return errNilHasher
		}
		s.hashers[version] = hasher
		return nil
	})
}

// Compare a given plaintext with a stored hash.
// Even if the match boolean returned is true, you may get an error ErrDeprecatedHash
// which signals that you should re-hash and store while we have access to the plaintext.
func (s *Stack) Compare(plaintext string, hash string) (match bool, err error) {
	// find the version. we prepend a 2 character HEX
	// it will be "xx:" prefix, in the first 3 characters
	var version uint8
	_, err = fmt.Sscanf(hash, "%02x:", &version)
	if err != nil {
		return false, ErrInvalidHash
	}
	hasher, ok := s.hashers[version]
	if !ok {
		return false, ErrUnknownVersion
	}
	pb, hb := []byte(plaintext), []byte(hash)
	// strip the version, the first 3 characters
	match, err = hasher.Compare(pb, hb[3:])

	if match && version != s.preferred {
		err = ErrDeprecatedHash
	}
	return
}

// Hash produces a storable string representing the current preferred
// hash of the given plaintext password.
// NB: Do not use this function to compare the resultant hash with a stored
// hash, it will not work
func (s *Stack) Hash(plaintext string) (hash string, err error) {
	hasher := s.hashers[s.preferred]
	b, err := hasher.Hash([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02x:%s", s.preferred, b), nil
}

// CompareAndUpdate encapsulates the logic for comparing a plaintext with a hash
// and creating a new hash if the old one is a deprecated version. The logic
// for updating a stored hash should be given in the updateFn argument which
// will only be called if the hash requires updating
func (s *Stack) CompareAndUpdate(plaintext, hash string, updateFn func(newHash string) error) (match bool, err error) {
	match, err = s.Compare(plaintext, hash)
	if err == ErrDeprecatedHash {
		var newHash string
		newHash, err = s.Hash(plaintext)
		if err == nil {
			err = updateFn(newHash)
		}
	}
	return
}
