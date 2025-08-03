package pbkdf2

// pbkdf2 package provides utilities for secure password hashing using configurable
// key derivation settings (iteration count, key length, hash function, and salt length).
// This implementation supports PBKDF2 with SHA-256 and SHA-512.

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// pwdConfig stores configuration options used for password hashing.
// - Iter:     Number of PBKDF2 iterations (higher is more secure but slower).
// - KeyLen:   Desired length (in bytes) of the derived key (hashed password).
// - Hash:     Hash function constructor (e.g., sha256.New).
// - SaltLen:  Length of salt to be generated for password hashing.
type pwdConfig struct {
	Iter    int
	KeyLen  int
	Hash    func() hash.Hash
	SaltLen int
}

// Global package-level configuration object.
// This will be set via SetPwdConfig and used throughout the package.
var (
	config        pwdConfig
	ErrPwdIter    = errors.New("iterations is set to negatice number")
	ErrComparePwd = errors.New("incorrect password")
)

// SetPwdConfig initializes or updates the global password hashing configuration.
//
// Parameters:
// - h:      Hash function name as a string ("SHA256", "SHA512").
// - itr:    Number of iterations for PBKDF2.
// - keyLen: Desired length of the derived key in bytes.
// - sLen:   Salt length in bytes.
//
// It sets default hash function to SHA-256 if an unknown hash type is provided.
func SetPwdConfig(h string, itr, keyLen, sLen int) {
	config = pwdConfig{
		Iter:    itr,
		KeyLen:  keyLen,
		SaltLen: sLen,
	}

	switch h {
	case "SHA256":
		config.Hash = sha256.New
	case "SHA512":
		config.Hash = sha512.New
	default:
		config.Hash = sha256.New
	}

}
