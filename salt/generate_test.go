package salt

import (
	"testing"
)

func TestGenerateSalt_DefaultLength(t *testing.T) {
	// Test with length 0, should default to 15
	salt, err := GenerateSalt(0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(salt) != 15 {
		t.Errorf("expected salt length 15, got %d", len(salt))
	}

	// Verify all characters are from allowed set
	for _, char := range string(salt) {
		if !isAllowedChar(char) {
			t.Errorf("salt contains invalid character: %c", char)
		}
	}
}

func TestGenerateSalt_SpecificLength(t *testing.T) {
	// Test with specific positive length
	length := 32
	salt, err := GenerateSalt(length)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(salt) != length {
		t.Errorf("expected salt length %d, got %d", length, len(salt))
	}

	// Verify all characters are from allowed set
	for _, char := range string(salt) {
		if !isAllowedChar(char) {
			t.Errorf("salt contains invalid character: %c", char)
		}
	}
}

func TestGenerateSalt_NegativeLength(t *testing.T) {
	// Test with negative length, should return error
	_, err := GenerateSalt(-1)
	if err != ErrSaltLength {
		t.Errorf("expected ErrSaltLength, got %v", err)
	}
}

func TestGenerateSalt_EmptySalt(t *testing.T) {
	// Test with length 0, should default to 15
	salt, err := GenerateSalt(0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(salt) == 0 {
		t.Error("expected non-empty salt")
	}
}

func TestGenerateSalt_Uniqueness(t *testing.T) {
	// Test that multiple generations produce different salts
	salt1, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	salt2, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if string(salt1) == string(salt2) {
		t.Error("expected different salts, got identical values")
	}
}

func TestGenerateSalt_CharacterSet(t *testing.T) {
	// Test that generated salt only contains allowed characters
	salt, err := GenerateSalt(50)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	allowedChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	for _, char := range string(salt) {
		if !containsChar(allowedChars, char) {
			t.Errorf("salt contains invalid character: %c", char)
		}
	}
}

// Helper function to check if a character is in the allowed set
func containsChar(allowed string, char rune) bool {
	for _, c := range allowed {
		if c == char {
			return true
		}
	}
	return false
}

// Helper function to check if a character is allowed
func isAllowedChar(char rune) bool {
	allowedChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for _, c := range allowedChars {
		if c == char {
			return true
		}
	}
	return false
}
