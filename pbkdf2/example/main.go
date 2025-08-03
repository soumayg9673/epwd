package main

import (
	"fmt"
	"log"

	"github.com/soumayg9673/epwd/pbkdf2"
)

func main() {
	// Configure password hashing parameters
	// Parameters: hash function, iterations, key length, salt length
	pbkdf2.SetPwdConfig("SHA256", 600000, 32, 16)

	// The password we want to hash
	password := []byte("mySecurePassword123")

	fmt.Println("Password Encryption and Comparison Example")
	fmt.Println("===========================================")
	fmt.Printf("Original password: %s\n", string(password))

	// Encrypt the password with auto-generated salt
	fmt.Println("\n1. Encrypting password with auto-generated salt...")
	hashedPassword, salt, err := pbkdf2.GeneratePasswordWithAutoSalt(password)
	if err != nil {
		log.Fatal("Error hashing password:", err)
	}

	fmt.Printf("Hashed password: %x\n", hashedPassword)
	fmt.Printf("Generated salt: %x\n", salt)

	// Verify the correct password
	fmt.Println("\n2. Verifying correct password...")
	err = pbkdf2.ComparePassword(password, hashedPassword, salt)
	if err != nil {
		fmt.Println("Password verification failed:", err)
	} else {
		fmt.Println("✓ Password verified successfully!")
	}

	// Try to verify an incorrect password
	fmt.Println("\n3. Verifying incorrect password...")
	wrongPassword := []byte("wrongPassword")
	err = pbkdf2.ComparePassword(wrongPassword, hashedPassword, salt)
	if err != nil {
		fmt.Println("✓ Password verification correctly failed for wrong password")
		fmt.Println("   Error:", err)
	} else {
		fmt.Println("Password verification unexpectedly succeeded")
	}

	// Example with custom salt
	fmt.Println("\n4. Encrypting password with custom salt...")
	// In practice, you would store this salt with the hashed password
	customSalt := []byte("customSalt123456")
	customHashedPassword, err := pbkdf2.GeneratePasswordWithSalt(password, customSalt)
	if err != nil {
		log.Fatal("Error hashing password with custom salt:", err)
	}

	fmt.Printf("Hashed password with custom salt: %x\n", customHashedPassword)

	// Verify with custom salt
	fmt.Println("\n5. Verifying password with custom salt...")
	err = pbkdf2.ComparePassword(password, customHashedPassword, customSalt)
	if err != nil {
		fmt.Println("Password verification failed:", err)
	} else {
		fmt.Println("✓ Password with custom salt verified successfully!")
	}

	fmt.Println("\nExample completed successfully!")
}
