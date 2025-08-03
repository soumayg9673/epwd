package salt

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const SALTALLOWEDCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	ErrSaltLength = errors.New("salt length is set to negative number")
)

// GenerateSalt generates a random salt of the given length using allowed characters.
// Returns an error if the provided length is negative.
func GenerateSalt(sl int) ([]byte, error) {

	// validate salt length config
	if sl == 0 {
		sl = 15
	} else if sl < 0 {
		return nil, ErrSaltLength
	}

	var salt string

	for range sl {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(SALTALLOWEDCHARS))))
		if err != nil {
			return nil, nil
		}
		salt += string(SALTALLOWEDCHARS[i.Int64()])
	}

	return []byte(salt), nil
}
