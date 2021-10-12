package stack

import (
	"testing"
)

const (
	plain         = "hunter2"
	argonHunter2  = `00:_K7uK0k8e7hAIhtyyg9kbw:21.FTJ2wtZJMVki4khAZHUTyXpU3qNb2cAdtMKIUeYCKww.MTksMSw2NTUzNiwy`
	scryptHunter2 = `01:M3EuJLWHMSVFn-HLlgnKGA:5c.Aij4o5dw-U0TPhsmo50YhzIiWNSJh0v-IQferpQG8y8.NjU1MzYsOCwx`
)

func TestArgon2id(t *testing.T) {
	scheme, err := New(DefaultArgon2idScheme_2021_10(0))
	if err != nil {
		t.Error(err)
	}
	hash, err := scheme.Hash(plain)
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("%s\n", hash)
	}

	match, _ := scheme.Compare(plain, hash)
	if !match {
		t.Error("argon Compare fail (with new hash)")
	}
	match, _ = scheme.Compare(plain, argonHunter2)
	if !match {
		t.Error("argon Compare fail (with stored hash)")
	}
}

func TestScrypt(t *testing.T) {

	scheme, err := New(DefaultScryptScheme_2021_10(1))
	if err != nil {
		t.Error(err)
	}

	hash, err := scheme.Hash(plain)
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("%s\n", hash)
	}

	match, _ := scheme.Compare(plain, hash)
	if !match {
		t.Error("scrypt Compare fail (with new hash)")
	}
	match, _ = scheme.Compare(plain, scryptHunter2)
	if !match {
		t.Error("scrypt Compare fail (with stored hash)")
	}
}

func TestSimpleStack(t *testing.T) {
	stack, _ := New(
		DefaultArgon2idScheme_2021_10(0),
		DefaultScryptScheme_2021_10(1),
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
	match, err = stack.Compare(plain, argonHunter2)
	if !match {
		t.Error("stack didn't match correctly (stored preferred hash)")
	}
	if err != nil {
		t.Error(err)
	}
	match, err = stack.Compare(plain, scryptHunter2)
	if !match {
		t.Error("stack didn't match correctly (stored deprecated hash)")
	}
	if err != ErrDeprecatedHash {
		t.Error("expecting deprecated hash warning")
	}
	test := "00:" + scryptHunter2[2:]
	match, err = stack.Compare(plain, test)
	if match {
		t.Errorf("stack matched incorrectly (invalid hash) (%s)", test)
	}
	if err != ErrInvalidHash {
		t.Error("expecting invalid hash warning, got", err)
	}

	test = "ff:" + scryptHunter2[2:]
	match, err = stack.Compare(plain, test)
	if match {
		t.Errorf("stack matched incorrectly (invalid hash version) (%s)", test)
	}
	if err != ErrUnknownVersion {
		t.Error("expecting unknown hash version warning")
	}

}
