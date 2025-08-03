package pbkdf2

import (
	"crypto/pbkdf2"
	"crypto/sha256"

	"github.com/soumayg9673/epwd/salt"
)

// GeneratePasswordWithAutoSalt hashes a password using PBKDF2 with a randomly generated salt.
// It returns the derived key (hashed password), the generated salt, and an error if any occurs.
//
// The function uses configurations from a global `config` object which should include:
// - Iter: Number of PBKDF2 iterations
// - SaltLen: Desired salt length
// - Hash: Hash function to use (defaults to SHA-256 if not set)
// - KeyLen: Desired length of the derived key
func GeneratePasswordWithAutoSalt(password []byte) ([]byte, []byte, error) {

	// If no iteration count is specified, set a secure default value (600,000 iterations).
	if config.Iter == 0 {
		config.Iter = 600000
	} else if config.Iter < 0 {
		return nil, nil, ErrPwdIter
	}

	// Generate a cryptographically secure random salt using the configured salt length.
	salt, err := salt.GenerateSalt(config.SaltLen)
	if err != nil {
		return nil, nil, err
	}

	// Use SHA-256 as the default hash function if none is explicitly provided.
	// This ensures consistency and avoids nil panics.
	if config.Hash == nil {
		config.Hash = sha256.New
	}

	// Derive a secure key from the password using PBKDF2 with the provided hash function,
	// salt, iteration count, and desired key length.
	// This process makes brute-force attacks significantly harder.
	dk, err := pbkdf2.Key(config.Hash, string(password), []byte(salt), config.Iter, config.KeyLen)
	if err != nil {
		return nil, nil, err
	}

	return dk, salt, nil
}

// GeneratePasswordWithSalt securely hashes a password using PBKDF2 with a user-provided salt.
// It uses the global `config` for parameters like iteration count, key length, and hash function.
//
// Parameters:
// - password: The plain-text password in byte slice form.
// - salt:     A cryptographically secure salt (must be consistent for password verification).
//
// Returns:
// - The derived key (hashed password) as a byte slice.
// - An error if the hashing process fails or configuration is invalid.
func GeneratePasswordWithSalt(password, salt []byte) ([]byte, error) {

	// Ensure the iteration count is set.
	// Default to 600,000 iterations if not explicitly provided.
	if config.Iter == 0 {
		config.Iter = 600000
	} else if config.Iter < 0 {
		return nil, ErrPwdIter
	}

	// Ensure a valid hash function is configured.
	// Default to SHA-256 if none is set, to prevent nil panics.
	if config.Hash == nil {
		config.Hash = sha256.New
	}

	// Perform key derivation using PBKDF2 with the configured hash function,
	// the provided password and salt, the specified iteration count, and key length.
	//
	// This operation is computationally expensive by design,
	// making brute-force and dictionary attacks more difficult.
	dk, err := pbkdf2.Key(config.Hash, string(password), salt, config.Iter, config.KeyLen)
	if err != nil {
		return nil, err
	}

	return dk, nil
}
