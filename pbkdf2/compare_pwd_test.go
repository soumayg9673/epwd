package pbkdf2

import (
	"testing"

	"github.com/soumayg9673/epwd/salt"
)

func TestComparePassword_Success(t *testing.T) {

	saltLength := 16
	keyLength := 32
	pwdIteration := 1000
	SetPwdConfig("SHA256", pwdIteration, keyLength, saltLength)

	password := []byte("testPassword123")

	// Generate salt and hash
	salt, err := salt.GenerateSalt(saltLength)
	if err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}
	hashedPwd, err := GeneratePasswordWithSalt(password, salt)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Should succeed
	err = ComparePassword(password, hashedPwd, salt)
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}
}

func TestComparePassword_Failure(t *testing.T) {

	saltLength := 16
	keyLength := 32
	pwdIteration := 1000
	SetPwdConfig("SHA256", pwdIteration, keyLength, saltLength)

	password := []byte("testPassword123")
	wrongPassword := []byte("wrongPassword")

	// Generate salt and hash
	salt, err := salt.GenerateSalt(saltLength)
	if err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}
	hashedPwd, err := GeneratePasswordWithSalt(password, salt)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Should fail
	err = ComparePassword(wrongPassword, hashedPwd, salt)
	if err == nil {
		t.Errorf("expected error, got none")
	}
}
