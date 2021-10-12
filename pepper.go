package stack

import (
	"crypto/hmac"
	"hash"

	"golang.org/x/crypto/sha3"
)

// the peppered hasher simply wraps the plaintext with an HMAC
type peppered struct {
	Hasher
	pepper []byte
}

func Peppered(s *Scheme, pepper []byte) *Scheme {
	s.Hasher = &peppered{
		Hasher: s.Hasher,
		pepper: pepper,
	}
	return s
}

func (p *peppered) Pepper(plaintext, salt []byte) []byte {
	plaintext = applyHmac(sha3.New384, plaintext, salt)
	plaintext = applyHmac(sha3.New384, plaintext, p.pepper)
	return plaintext
}

func applyHmac(h func() hash.Hash, plain, key []byte) []byte {
	m := hmac.New(h, key)
	m.Write(plain)
	return m.Sum(plain)
}
