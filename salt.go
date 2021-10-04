package stack

import "crypto/rand"

func generateSalt(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b[:])
	return b, err
}
