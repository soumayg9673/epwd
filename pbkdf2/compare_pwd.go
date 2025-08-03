package pbkdf2

import "crypto/subtle"

func ComparePassword(currentPwd, hashedPwd, salt []byte) error {

	// Encrypt current password
	hashCurrentPwd, err := GeneratePasswordWithSalt(currentPwd, salt)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(hashCurrentPwd, hashedPwd) == 0 {
		return ErrComparePwd
	}

	return nil
}
