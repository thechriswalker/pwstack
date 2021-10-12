package stack

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams allows advanced configuration of the Argon2id
// hash. Some sane defaults exist with DefaultArgon2idParamsXXXX for
// the highest year/date that exists when you start. They are
// guarranteed to remain stable across versions of this library.
type Argon2idParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32

	// we cache this.
	encodedParams []byte
}

// The current defaults as of October 2021 (library creation)
func DefaultArgon2idScheme_2021_10(version uint8) *Scheme {
	return &Scheme{
		Version: version,
		Hasher: &Argon2idParams{
			Time:    1,
			Memory:  64 * 1024,
			Threads: 2, // in the cloud, we may not have too many CPUs available
			SaltLen: 16,
			KeyLen:  32,
		},
	}
}

var (
	_ Hasher = (*Argon2idParams)(nil)
)

const argon2idHashID = 0x21

func (h *Argon2idParams) params() []byte {
	if h.encodedParams == nil {
		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%d,%d,%d,%d", argon2.Version, h.Time, h.Memory, h.Threads)
		h.encodedParams = make([]byte, base64.RawURLEncoding.EncodedLen(buf.Len()))
		base64.RawURLEncoding.Encode(h.encodedParams, buf.Bytes())
	}
	return h.encodedParams
}

func (h *Argon2idParams) Hash(plain, salt []byte) ([]byte, error) {
	if len(salt) != int(h.SaltLen) {
		return nil, errInvalidSalt
	}
	return encode(&unserialized{
		hashid: argon2idHashID,
		hash:   argon2.IDKey(plain, salt, h.Time, h.Memory, h.Threads, h.KeyLen),
		params: h.params(),
	}), nil
}

func (h *Argon2idParams) SaltSize() int {
	return int(h.SaltLen)
}
