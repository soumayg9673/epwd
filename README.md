# epwd - Secure Password Hashing Library

[![Go Reference](https://pkg.go.dev/badge/github.com/soumayg9673/epwd.svg)](https://pkg.go.dev/github.com/soumayg9673/epwd)
[![Go Report Card](https://goreportcard.com/badge/github.com/soumayg9673/epwd)](https://goreportcard.com/report/github.com/soumayg9673/epwd)

A Go library for secure password hashing using PBKDF2 with configurable parameters. This library provides robust password hashing and verification capabilities with protection against common security vulnerabilities.

## Features

- 🔒 PBKDF2 implementation with SHA-256 and SHA-512 support
- 🛡️ Protection against timing attacks with constant-time comparison
- ⚙️ Configurable iterations, key length, and salt length
- 🔄 Automatic salt generation or user-provided salt support
- 📦 Easy to use API with comprehensive error handling

## Installation

```bash
go get github.com/soumayg9673/epwd
```

## Usage

### Basic Password Hashing

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/soumayg9673/epwd/pbkdf2"
)

func main() {
    // Set configuration (optional)
    pbkdf2.SetPwdConfig("SHA256", 600000, 32, 16)
    
    // Hash a password with auto-generated salt
    password := []byte("mySecurePassword")
    hash, salt, err := pbkdf2.GeneratePasswordWithAutoSalt(password)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Hash: %x\n", hash)
    fmt.Printf("Salt: %x\n", salt)
}
```

### Password Verification

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/soumayg9673/epwd/pbkdf2"
)

func main() {
    // Assume we have stored hash and salt from previous example
    storedHash := []byte{/* stored hash bytes */}
    storedSalt := []byte{/* stored salt bytes */}
    userInput := []byte("mySecurePassword")
    
    // Verify password
    err := pbkdf2.ComparePassword(userInput, storedHash, storedSalt)
    if err != nil {
        fmt.Println("Incorrect password")
        return
    }
    
    fmt.Println("Password verified successfully")
}
```

### Using Custom Salt

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/soumayg9673/epwd/pbkdf2"
    "github.com/soumayg9673/epwd/salt"
)

func main() {
    // Generate a custom salt
    customSalt, err := salt.GenerateSalt(32)
    if err != nil {
        log.Fatal(err)
    }
    
    // Hash password with custom salt
    password := []byte("mySecurePassword")
    hash, err := pbkdf2.GeneratePasswordWithSalt(password, customSalt)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Hash with custom salt: %x\n", hash)
}
```

## Configuration

The library can be configured using `SetPwdConfig`:

```go
pbkdf2.SetPwdConfig(hashFunction, iterations, keyLength, saltLength)
```

Parameters:
- `hashFunction`: Hash algorithm ("SHA256" or "SHA512")
- `iterations`: Number of PBKDF2 iterations (higher = more secure but slower)
- `keyLength`: Length of derived key in bytes
- `saltLength`: Length of salt in bytes

Default values:
- Hash function: SHA256
- Iterations: 600,000
- Key length: 32 bytes
- Salt length: 16 bytes

## Functions

### pbkdf2 package

- `SetPwdConfig(h string, itr, keyLen, sLen int)`: Configure password hashing parameters
- `GeneratePasswordWithAutoSalt(password []byte) ([]byte, []byte, error)`: Generate hash with auto-generated salt
- `GeneratePasswordWithSalt(password, salt []byte) ([]byte, error)`: Generate hash with provided salt
- `ComparePassword(currentPwd, hashedPwd, salt []byte) error`: Securely compare password with hash

### salt package

- `GenerateSalt(length int) ([]byte, error)`: Generate random salt of specified length

## Security Considerations

1. **Iteration Count**: The default 600,000 iterations provide strong protection against brute-force attacks. Adjust based on your security requirements and performance constraints.

2. **Salt**: Always use a unique salt for each password. This library provides automatic salt generation to prevent rainbow table attacks.

3. **Timing Attacks**: Password comparison uses constant-time comparison to prevent timing-based attacks.

4. **Memory Safety**: The library handles sensitive data appropriately without exposing it in logs or error messages.

## License

This project is licensed under the BSD 3 License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
