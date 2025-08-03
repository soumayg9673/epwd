package pbkdf2

import "crypto/subtle"

// ComparePassword securely verifies whether the provided plain-text password matches
// the previously hashed password using the original salt.
//
// Parameters:
// - currentPwd: The user-supplied password input (plain-text, as []byte).
// - hashedPwd:  The stored hashed password to compare against.
// - salt:       The original salt used during hashing (must match the salt used to generate `hashedPwd`).
//
// Returns:
// - nil if the password is correct (matches the hash).
// - ErrComparePwd if the password is incorrect.
// - Any error returned by the hashing process.
func ComparePassword(currentPwd, hashedPwd, salt []byte) error {

	// Hash the current plain-text password using the same salt and config.
	// This recreates the expected hash for comparison.
	hashCurrentPwd, err := GeneratePasswordWithSalt(currentPwd, salt)
	if err != nil {
		return err
	}

	// Perform constant-time comparison between the stored hash and the newly generated one.
	// This avoids timing attacks by ensuring the comparison time is independent of the actual content.
	if subtle.ConstantTimeCompare(hashCurrentPwd, hashedPwd) == 0 {
		return ErrComparePwd
	}

	return nil
}
