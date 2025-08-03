package pbkdf2

import (
	"crypto/pbkdf2"
	"crypto/sha256"

	"github.com/soumayg9673/epwd/salt"
)

func GeneratePasswordWithAutoSalt(password []byte) ([]byte, []byte, error) {

	// Set password iteration count
	if config.Iter == 0 {
		config.Iter = 600000
	} else if config.Iter < 0 {
		return nil, nil, ErrPwdIter
	}

	// Generate random salt
	salt, err := salt.GenerateSalt(config.SaltLen)
	if err != nil {
		return nil, nil, err
	}

	// Set SHA256 default when Hash is nil/empty.
	if config.Hash == nil {
		config.Hash = sha256.New
	}

	// Encrypt password
	dk, err := pbkdf2.Key(config.Hash, string(password), []byte(salt), config.Iter, config.KeyLen)
	if err != nil {
		return nil, nil, err
	}

	return dk, salt, nil
}

func GeneratePasswordWithSalt(password, salt []byte) ([]byte, error) {

	// Validate iteration count
	if config.Iter == 0 {
		config.Iter = 600000
	} else if config.Iter < 0 {
		return nil, ErrPwdIter
	}

	// Set SHA256 default when Hash is nil/empty.
	if config.Hash == nil {
		config.Hash = sha256.New
	}

	// Encrypt password
	dk, err := pbkdf2.Key(config.Hash, string(password), salt, config.Iter, config.KeyLen)
	if err != nil {
		return nil, err
	}

	return dk, nil
}
