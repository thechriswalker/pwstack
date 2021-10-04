package stack

import (
	"testing"
)

const (
	plain         = "hunter2"
	argonHunter2  = `2id:TcT5l2O9_nxXGEh6Cgj3zg:19,1,65536,2:i4BZc_QMsCJICiIWd7P15VxNigAtjefNI9fMCajnxqc`
	scryptHunter2 = `sc:_zstkyE7w7QvG6zxKbIRKA:65536,8,1:8bBzXrAdjXnfTesM-yE3YkLaTpJiKWpb3PhYMfiZ544`
)

func TestArgon2id(t *testing.T) {

	h := DefaultArgon2idParams_2021_10()
	hash, err := h.Hash([]byte(plain))
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("%s\n", hash)
	}

	match, _ := h.Compare([]byte(plain), hash)
	if !match {
		t.Error("argon Compare fail (with new hash)")
	}
	match, _ = h.Compare([]byte(plain), []byte(argonHunter2))
	if !match {
		t.Error("argon Compare fail (with stored hash)")
	}
}

func TestScrypt(t *testing.T) {

	h := DefaultScryptParams_2021_10()

	hash, err := h.Hash([]byte(plain))
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("%s\n", hash)
	}

	match, _ := h.Compare([]byte(plain), hash)
	if !match {
		t.Error("scrypt Compare fail (with new hash)")
	}
	match, _ = h.Compare([]byte(plain), []byte(scryptHunter2))
	if !match {
		t.Error("scrypt Compare fail (with stored hash)")
	}
}

func TestSimpleStack(t *testing.T) {
	stack, _ := New(
		WithPreferred(0x02, DefaultArgon2idParams_2021_10()),
		WithDeprecated(0x01, DefaultScryptParams_2021_10()),
	)

	hash, err := stack.Hash(plain)
	if err != nil {
		t.Error(err)
	}

	match, err := stack.Compare(plain, hash)
	if !match {
		t.Error("stack didn't match correctly (new hash)")
	}
	if err != nil {
		t.Error(err)
	}
	match, err = stack.Compare(plain, "02:"+argonHunter2)
	if !match {
		t.Error("stack didn't match correctly (stored preferred hash)")
	}
	if err != nil {
		t.Error(err)
	}
	match, err = stack.Compare(plain, "01:"+scryptHunter2)
	if !match {
		t.Error("stack didn't match correctly (stored deprecated hash)")
	}
	if err != ErrDeprecatedHash {
		t.Error("expecting deprecated hash warning")
	}
	match, err = stack.Compare(plain, "02:"+scryptHunter2)
	if match {
		t.Error("stack matched incorrectly (invalid hash)")
	}
	if err != ErrInvalidHash {
		t.Error("expecting invalid hash wanring")
	}
	match, err = stack.Compare(plain, "ff:"+scryptHunter2)
	if match {
		t.Error("stack matched incorrectly (invalid hash version)")
	}
	if err != ErrUnknownVersion {
		t.Error("expecting unknown hash version wanring")
	}

}
