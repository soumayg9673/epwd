package pbkdf2

import (
	"testing"

	"github.com/soumayg9673/epwd/salt"
)

func TestGeneratePasswordWithAutoSalt_Success(t *testing.T) {

	saltLength := 16
	keyLength := 32
	pwdIteration := 600000
	SetPwdConfig("SHA256", pwdIteration, keyLength, saltLength)

	password := []byte("testPassword123")

	dk, salt, err := GeneratePasswordWithAutoSalt(password)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(dk) != keyLength {
		t.Errorf("expected derived key length %d, got %d", keyLength, len(dk))
	}
	if len(salt) != saltLength {
		t.Errorf("expected salt length %d, got %d", saltLength, len(salt))
	}
}

func TestGeneratePasswordWithAutoSalt_InvalidIter(t *testing.T) {

	saltLength := 16
	keyLength := 32
	pwdIteration := -1
	SetPwdConfig("SHA256", pwdIteration, keyLength, saltLength)

	password := []byte("testPassword123")

	_, _, err := GeneratePasswordWithAutoSalt(password)
	if err == nil {
		t.Errorf("expected error for negative iteration count, got nil")
	}
}

func TestGeneratePasswordWithSalt_Success(t *testing.T) {

	saltLength := 16
	keyLength := 32
	pwdIteration := 1000
	SetPwdConfig("SHA256", pwdIteration, keyLength, saltLength)

	password := []byte("testPassword123")

	salt, err := salt.GenerateSalt(saltLength)
	if err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}

	dk, err := GeneratePasswordWithSalt(password, salt)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(dk) != keyLength {
		t.Errorf("expected derived key length %d, got %d", keyLength, len(dk))
	}
}

func TestGeneratePasswordWithSalt_InvalidIter(t *testing.T) {

	saltLength := 22
	keyLength := 32
	pwdIteration := -1
	SetPwdConfig("SHA256", pwdIteration, keyLength, saltLength)

	password := []byte("testPassword123")
	salt := []byte("somerandomsalt")

	_, err := GeneratePasswordWithSalt(password, salt)
	if err == nil {
		t.Errorf("expected error for negative iteration count, got nil")
	}
}
