package stack

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"

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
}

func DefaultScryptParams_2021_10() *ScryptParams {
	return &ScryptParams{
		N:       1 << 16,
		R:       8,
		P:       1,
		SaltLen: 16,
		KeyLen:  32,
	}
}

var (
	_ Hasher      = (*ScryptParams)(nil)
	_ KeyedHasher = (*ScryptParams)(nil)
)

const (
	scryptHashID             = "sc"
	scryptHashParamSeparator = ':'
)

func (h *ScryptParams) Hash(plain []byte) ([]byte, error) {
	return h.KeyedHash(plain, nil)
}
func (h *ScryptParams) KeyedHash(plain []byte, key Keyer) ([]byte, error) {
	salt, err := generateSalt(h.SaltLen)
	if err != nil {
		return nil, err
	}
	raw, err := h.rawHash(plain, salt, key)
	if err != nil {
		return nil, err
	}
	final := new(bytes.Buffer)
	final.Write([]byte(scryptHashID))
	final.WriteByte(scryptHashParamSeparator)
	salt64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(salt)))
	base64.RawURLEncoding.Encode(salt64, salt)
	final.Write(salt64)
	final.WriteByte(scryptHashParamSeparator)
	h.encodeParams(final)
	final.WriteByte(scryptHashParamSeparator)
	raw64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(raw64, raw)
	final.Write(raw64)

	return final.Bytes(), nil
}

func (h *ScryptParams) Compare(plain, hash []byte) (bool, error) {
	return h.KeyedCompare(plain, hash, nil)
}

func (h *ScryptParams) KeyedCompare(plain, hash []byte, key Keyer) (bool, error) {
	// decode Hash to salt, raw and validate params
	salt, raw, ok := h.decodeHash(hash)
	// if identifier mismatch, bail early.
	// parameter mismatch, bail early.
	if !ok {
		return false, ErrInvalidHash
	}
	expected, err := h.rawHash(plain, salt, key)
	if err != nil {
		// bad, but we have to return false.
		// however, the function will only return false if the parameters
		// are invalid
		return false, ErrInvalidHash
	}
	return subtle.ConstantTimeCompare(raw, expected) == 1, nil
}

func (h *ScryptParams) encodeParams(wr io.Writer) error {
	_, err := fmt.Fprintf(wr, "%d,%d,%d", h.N, h.R, h.P)
	return err
}

func (h *ScryptParams) rawHash(plain, salt []byte, keyer Keyer) ([]byte, error) {
	if keyer != nil {
		plain = keyer.Key(plain, salt)
	}
	return scrypt.Key(plain, salt, h.N, h.R, h.P, h.KeyLen)
}

func (h *ScryptParams) decodeHash(hash []byte) (salt []byte, key []byte, ok bool) {
	// we don't care what the params in the hash _are_, only if they are different
	fields := bytes.FieldsFunc(hash, func(r rune) bool { return r == scryptHashParamSeparator })
	if len(fields) != 4 {
		return
	}
	// first check the id
	id, b64salt, params, b64key := fields[0], fields[1], fields[2], fields[3]
	if !bytes.Equal(id, []byte(scryptHashID)) {
		return
	}
	// now, do the parameters match?
	expectedParams := bytes.NewBuffer(make([]byte, 0, len(params)))
	err := h.encodeParams(expectedParams)
	if err != nil {
		return
	}
	if !bytes.Equal(params, expectedParams.Bytes()) {
		// nope
		return
	}
	// check the lengths of salt and hash
	if base64.RawURLEncoding.DecodedLen(len(b64salt)) != int(h.SaltLen) {
		return
	}
	if base64.RawURLEncoding.DecodedLen(len(b64key)) != int(h.KeyLen) {
		return
	}
	// OK, it is correct length, is it valid b64?
	salt = make([]byte, h.SaltLen)
	if _, err := base64.RawURLEncoding.Decode(salt, b64salt); err != nil {
		return
	}
	// what about the key
	key = make([]byte, h.KeyLen)
	if _, err := base64.RawURLEncoding.Decode(key, b64key); err != nil {
		return
	}
	// all good
	ok = true
	return
}
