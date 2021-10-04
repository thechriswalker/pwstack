package stack

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"

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
}

// The current defaults as of October 2021 (library creation)
func DefaultArgon2idParams_2021_10() *Argon2idParams {
	return &Argon2idParams{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 2, // in the cloud, we may not have too many CPUs available
		SaltLen: 16,
		KeyLen:  32,
	}
}

var (
	_ Hasher      = (*Argon2idParams)(nil)
	_ KeyedHasher = (*Argon2idParams)(nil)
)

const (
	argon2idHashID        = "2id"
	argon2idHashSeperator = ':'
)

func (h *Argon2idParams) encodeParams(wr io.Writer) error {
	_, err := fmt.Fprintf(wr, "%d,%d,%d,%d", argon2.Version, h.Time, h.Memory, h.Threads)
	return err
}

func (h *Argon2idParams) Hash(plain []byte) ([]byte, error) {
	return h.KeyedHash(plain, nil)
}

func (h *Argon2idParams) KeyedHash(plain []byte, keyer Keyer) ([]byte, error) {
	// generate a salt
	salt, err := generateSalt(int(h.SaltLen))
	if err != nil {
		return nil, err
	}
	raw := h.keyedHash(plain, salt, keyer)
	final := new(bytes.Buffer)
	final.Write([]byte(argon2idHashID))
	final.WriteByte(argon2idHashSeperator)
	salt64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(salt)))
	base64.RawURLEncoding.Encode(salt64, salt)
	final.Write(salt64)
	final.WriteByte(argon2idHashSeperator)
	h.encodeParams(final)
	final.WriteByte(argon2idHashSeperator)
	raw64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(raw64, raw)
	final.Write(raw64)

	return final.Bytes(), nil
}

func (h *Argon2idParams) Compare(plain, hash []byte) (bool, error) {
	return h.KeyedCompare(plain, hash, nil)
}

func (h *Argon2idParams) KeyedCompare(plain, hash []byte, keyer Keyer) (bool, error) {
	// introspect the hash for parameters
	salt, subhash, ok := h.decodeHash(hash)
	// if identifier mismatch, bail early.
	// parameter mismatch, bail early.
	if !ok {
		return false, ErrInvalidHash
	}
	expected := h.keyedHash(plain, salt, keyer)
	return subtle.ConstantTimeCompare(subhash, expected) == 1, nil
}

func (h *Argon2idParams) keyedHash(plain, salt []byte, keyer Keyer) []byte {
	if keyer != nil {
		plain = keyer.Key(plain, salt)
	}
	return argon2.IDKey(plain, salt, h.Time, h.Memory, h.Threads, h.KeyLen)
}

// the hash is in the form:
//
// `<hash_id>:<salt|b64>:<params=t,m,t,s,k>:<hash|b64>`
func (h *Argon2idParams) decodeHash(hash []byte) (salt []byte, key []byte, ok bool) {
	// we don't care what the params in the hash _are_, only if they are different
	fields := bytes.FieldsFunc(hash, func(r rune) bool { return r == argon2idHashSeperator })
	if len(fields) != 4 {
		//	log.Println("argon2id - hash field count error: expected 4, got", len(fields))
		return
	}
	// first check the id
	id, b64salt, params, b64key := fields[0], fields[1], fields[2], fields[3]
	if !bytes.Equal(id, []byte(argon2idHashID)) {
		//	log.Println("argon2id - hash ID mismatch")
		return
	}
	// now, do the parameters match?
	expectedParams := bytes.NewBuffer(make([]byte, 0, len(params)))
	err := h.encodeParams(expectedParams)
	if err != nil {
		//	log.Println("argon2id - params error:", err)
		return
	}
	if !bytes.Equal(params, expectedParams.Bytes()) {
		// nope
		//	log.Println("argon2id - params mismatch:", params, expectedParams)
		return
	}
	// check the lengths of salt and hash
	if base64.RawURLEncoding.DecodedLen(len(b64salt)) != int(h.SaltLen) {
		//	log.Println("argon2id - salt len mismatch")
		return
	}
	if base64.RawURLEncoding.DecodedLen(len(b64key)) != int(h.KeyLen) {
		//	log.Println("argon2id - key len mismatch")
		return
	}
	// OK, it is correct length, is it valid b64?
	salt = make([]byte, h.SaltLen)
	if _, err := base64.RawURLEncoding.Decode(salt, b64salt); err != nil {
		//	log.Println("argon2id - salt base64 invalid")
		return
	}
	// what about the key
	key = make([]byte, h.KeyLen)
	if _, err := base64.RawURLEncoding.Decode(key, b64key); err != nil {
		//	log.Println("argon2id - raw base64 invalid")
		return
	}
	//log.Println("argon2id - hash OK")
	// all good
	ok = true
	return
}
