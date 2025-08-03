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

func GenerateSalt(sl int) (string, error) {

	// validate salt length config
	if sl == 0 {
		sl = 15
	} else if sl < 0 {
		return "", ErrSaltLength
	}

	var salt string

	for range sl {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(SALTALLOWEDCHARS))))
		if err != nil {
			return "", nil
		}
		salt += string(SALTALLOWEDCHARS[i.Int64()])
	}

	return salt, nil
}
