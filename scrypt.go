package stack

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// ScryptParams describe a scrypt based password hash.
// the parameters have some rules and will error if invalid
// Whilst still a reasonable choice for password hashing,
// Argon2id is preferred and scrypt is provided as helper
// for migrating legacy hashes
type ScryptParams struct {
	N, R, P int
	SaltLen int
	KeyLen  int

	// cached params
	encodedParams []byte
}

func DefaultScryptScheme_2021_10(version uint8) *Scheme {
	return &Scheme{
		Version: version,
		Hasher: &ScryptParams{
			N:       1 << 16,
			R:       8,
			P:       1,
			SaltLen: 16,
			KeyLen:  32,
		},
	}
}

var (
	_ Hasher = (*ScryptParams)(nil)
)

const scryptHashID = 0x5c

func (h *ScryptParams) params() []byte {
	if h.encodedParams == nil {
		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%d,%d,%d", h.N, h.R, h.P)
		h.encodedParams = make([]byte, base64.RawURLEncoding.EncodedLen(buf.Len()))
		base64.RawURLEncoding.Encode(h.encodedParams, buf.Bytes())
	}
	return h.encodedParams
}

func (h *ScryptParams) Hash(plain, salt []byte) ([]byte, error) {
	if len(salt) != int(h.SaltLen) {
		return nil, errInvalidSalt
	}

	raw, err := scrypt.Key(plain, salt, h.N, h.R, h.P, h.KeyLen)
	if err != nil {
		return nil, err
	}

	return encode(&unserialized{
		hashid: scryptHashID,
		hash:   raw,
		params: h.params(),
	}), nil
}

func (h *ScryptParams) SaltSize() int {
	return h.SaltLen
}
