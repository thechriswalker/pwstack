package stack

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/sha3"
	"golang.org/x/text/unicode/norm"
)

// Stack represents a password hashing system, which may support more than
// one method of password hashing over time.
type Stack struct {
	preferred uint8
	schemes   map[uint8]*Scheme
}

// Represents a version of password storage
type Scheme struct {
	Version uint8
	Hasher  Hasher
}

func (s *Scheme) Hash(plaintext string) (string, error) {
	salt, err := generateSalt(s.Hasher.SaltSize())
	if err != nil {
		return "", err
	}
	// we should perform a unicode normalization on the text
	return s.hash(norm.NFC.Bytes([]byte(plaintext)), salt)
}

func (s *Scheme) hash(pt, salt []byte) (string, error) {
	if pp, ok := s.Hasher.(Pepperer); ok {
		pt = pp.Pepper(pt, salt)
	}
	output, err := s.Hasher.Hash(pt, salt)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02x:%s:%s", s.Version, base64.RawURLEncoding.EncodeToString(salt), output), nil
}

func (s *Scheme) HashWithAdditionalData(plaintext, additionalData string) (string, error) {
	salt, err := generateSalt(s.Hasher.SaltSize())
	if err != nil {
		return "", err
	}
	// we do the unicode normalisation here, before we add the additional data
	pt := norm.NFC.Bytes([]byte(plaintext))
	if ade, ok := s.Hasher.(AdditionalDataEncoder); ok {
		pt = ade.EncodeAdditionalData(pt, []byte(additionalData))
	} else {
		// ignore? use default.
		pt = applyHmac(sha3.New512, pt, []byte(additionalData))
	}
	return s.hash(pt, salt)
}

func (s *Scheme) CompareWithAdditionalData(plaintext, hash, additionalData string) (bool, error) {
	// normalize first
	pt := norm.NFC.Bytes([]byte(plaintext))
	if ade, ok := s.Hasher.(AdditionalDataEncoder); ok {
		pt = ade.EncodeAdditionalData(pt, []byte(additionalData))
	} else {
		// ignore? use default.
		pt = applyHmac(sha3.New512, pt, []byte(additionalData))
	}
	return s.compare(pt, []byte(hash))
}
func (s *Scheme) Compare(plaintext, hash string) (bool, error) {
	//normalize first
	pt := norm.NFC.Bytes([]byte(plaintext))
	return s.compare(pt, []byte(hash))
}

func (s *Scheme) compare(pt, hash []byte) (bool, error) {
	// we need to extract the salt to to get the
	saltLen := base64.RawURLEncoding.EncodedLen(s.Hasher.SaltSize())
	salt := make([]byte, s.Hasher.SaltSize())
	// the offset will be 3 characters for the version and colon, then
	_, err := base64.RawURLEncoding.Decode(salt, hash[3:3+saltLen])
	if err != nil {
		return false, ErrInvalidHash
	}
	if pp, ok := s.Hasher.(Pepperer); ok {
		pt = pp.Pepper(pt, salt)
	}
	output, err := s.Hasher.Hash(pt, salt)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(output, hash[4+saltLen:]) == 1, nil
}

// Hasher is the interface that all the password hashing
// schemes must implement, note that this is low level, providing the salt
// NB the "hash" output should not include the salt, as we will store that externally.
// we need it for our "pepper" step.
type Hasher interface {
	Hash(plaintext, salt []byte) (hash []byte, err error)
	SaltSize() int
}

// AdditionalDataEncoder allows the Hasher to provide a non-standard way to encode additional data
// the default mechanism is a HMAC with sha3-512
type AdditionalDataEncoder interface {
	EncodeAdditionalData(plain, additional []byte) []byte
}

// Pepperer, similarly allows the Hasher to provide a custom peppering function.
// By default no peppering is done.
type Pepperer interface {
	Pepper(plain, salt []byte) []byte
}

// New Password Scheme Stack with a given "preferred" Scheme and
// any number (well, not more than 254) of deprecated schemes.
func New(preferred *Scheme, deprecated ...*Scheme) (*Stack, error) {
	// check nil scheme...
	if preferred == nil {
		return nil, errNilScheme
	}
	s := &Stack{
		preferred: preferred.Version,
		schemes: map[uint8]*Scheme{
			preferred.Version: preferred,
		},
	}
	// now loop over deprecated
	for _, scheme := range deprecated {
		if scheme == nil {
			return nil, errNilScheme
		}
		if _, exists := s.schemes[scheme.Version]; exists {
			return nil, errDuplicateVersion
		}
		s.schemes[scheme.Version] = scheme
	}

	return s, nil
}

// Compare a given plaintext with a stored hash.
// Even if the match boolean returned is true, you may get an error ErrDeprecatedHash
// which signals that you should re-hash and store while we have access to the plaintext.
func (s *Stack) Compare(plaintext, hash string) (match bool, err error) {
	// find the version. we prepend a 2 character HEX
	// it will be "xx:" prefix, in the first 3 characters
	var version uint8
	_, err = fmt.Sscanf(hash, "%02x:", &version)
	if err != nil {
		return false, ErrInvalidHash
	}
	scheme, ok := s.schemes[version]
	if !ok {
		return false, ErrUnknownVersion
	}
	match, err = scheme.Compare(plaintext, hash)
	if match && version != s.preferred {
		err = ErrDeprecatedHash
	}
	return
}

// CompareWithAdditionalData compares a given plaintext with given additional data against a stored hash.
// Even if the match boolean returned is true, you may get an error ErrDeprecatedHash
// which signals that you should re-hash and store while we have access to the plaintext.
func (s *Stack) CompareWithAdditionalData(plaintext string, hash string, additionalData string) (match bool, err error) {
	// find the version. we prepend a 2 character HEX
	// it will be "xx:" prefix, in the first 3 characters
	var version uint8
	_, err = fmt.Sscanf(hash, "%02x:", &version)
	if err != nil {
		return false, ErrInvalidHash
	}
	scheme, ok := s.schemes[version]
	if !ok {
		return false, ErrUnknownVersion
	}
	match, err = scheme.CompareWithAdditionalData(plaintext, hash, additionalData)
	if match && version != s.preferred {
		err = ErrDeprecatedHash
	}
	return
}

// Hash produces a storable string representing the current preferred
// hash of the given plaintext password.
// NB: Do not use this function to compare the resultant hash with a stored
// hash, it will not work as the salt will not match.
func (s *Stack) Hash(plaintext string) (hash string, err error) {
	return s.schemes[s.preferred].Hash(plaintext)
}

// HashWithAdditionalData produces a storable string representing the current preferred
// hash of the given plaintext password when the additional data is mixed in.
// NB: Do not use this function to compare the resultant hash with a stored
// hash, it will not work as the salt will not match
func (s *Stack) HashWithAdditionalData(plaintext, additionalData string) (hash string, err error) {
	return s.schemes[s.preferred].HashWithAdditionalData(plaintext, additionalData)
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

// CompareAndUpdateWithAdditionalData encapsulates the logic for comparing a plaintext
// and additional data with a stored hash and creating a new hash if the old one is a
// deprecated version. The logic for updating a stored hash should be given in the
// updateFn argument which will only be called if the hash requires updating.
func (s *Stack) CompareAndUpdateWithAdditionalData(plaintext, hash, additionalData string, updateFn func(string) error) (match bool, err error) {
	match, err = s.CompareWithAdditionalData(plaintext, hash, additionalData)
	if err == ErrDeprecatedHash {
		var newHash string
		newHash, err = s.HashWithAdditionalData(plaintext, additionalData)
		if err == nil {
			err = updateFn(newHash)
		}
	}
	return
}
