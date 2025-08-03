package epwd

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type pwdConfig struct {
	Iter    int
	KeyLen  int
	Hash    func() hash.Hash
	SaltLen int
}

var config pwdConfig

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
