package stack

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

type unserialized struct {
	hashid uint8
	hash   []byte
	params []byte
}

func encode(u *unserialized) []byte {
	data := make([]byte, 0, len(u.hash))
	data = append(data, u.hash...)
	b64len := base64.RawURLEncoding.EncodedLen(len(data))
	encoded := bytes.NewBuffer(make([]byte, 0, 2+b64len+len(u.params)))
	fmt.Fprintf(encoded, "%02x.%s.", u.hashid, base64.RawURLEncoding.EncodeToString(data))
	encoded.Write(u.params)
	return encoded.Bytes()
}
