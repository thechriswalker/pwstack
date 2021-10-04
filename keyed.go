package stack

import (
	"crypto/hmac"
	"hash"
)

// KeyedHasher implementors can be wrapped with Keyed(instance) to
// produce a Hasher that supports a Keyed implementation
type KeyedHasher interface {
	KeyedHash(plaintext []byte, key Keyer) (hash []byte, err error)
	KeyedCompare(plaintext, hash []byte, key Keyer) (bool, error)
}

type keyed struct {
	h KeyedHasher
	k Keyer
}

// Keyer interface allows access to the salt,
// when applying the plaintext transform for a Keyed
// password
type Keyer interface {
	Key(plain, salt []byte) []byte
}

func (kh *keyed) Hash(plain []byte) ([]byte, error) {
	return kh.h.KeyedHash(plain, kh.k)
}
func (kh *keyed) Compare(plain, hash []byte) (bool, error) {
	return kh.h.KeyedCompare(plain, hash, kh.k)
}

var _ Hasher = (*keyed)(nil)

// Keyed creates a HMAC based secret-key version of the given
// hasher, provided it supports a keyed implementation
func Keyed(h KeyedHasher, k Keyer) Hasher {
	return &keyed{h: h, k: k}
}

type keyerFn func(plain, salt []byte) []byte

func (kf keyerFn) Key(plain, salt []byte) []byte {
	return kf(plain, salt)
}

// HmacKey creates a Keyer for keyed password hashes
// which uses an HMAC based method
func HmacKey(key []byte, h func() hash.Hash) Keyer {
	return keyerFn(func(plain, salt []byte) []byte {
		m := hmac.New(h, salt)
		// this should not error, the internal hmac code writes without watching for errors
		m.Write(plain)
		plain = m.Sum(nil)
		m = hmac.New(h, key)
		m.Write(plain)
		return m.Sum(nil)
	})
}
