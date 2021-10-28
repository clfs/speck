// Package speck implements the Speck cipher.
package speck

import (
	"crypto/cipher"
	"strconv"
)

type KeySizeError int

func (k KeySizeError) Error() string {
	return "speck: invalid key size " + strconv.Itoa(int(k))
}

func newCipher(key []byte, blocksize int) (cipher.Block, error) {
	return nil, nil
}

// NewCipher32 creates and returns a new cipher.Block.
// The block size is 32 bits.
// The key argument should be 64 bits.
func NewCipher32(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 8:
		break
	}
	return newCipher(key, 32)
}

// NewCipher48 creates and returns a new cipher.Block.
// The block size is 48 bits.
// The key argument should be either 72 or 96 bits.
func NewCipher48(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 9, 12:
		break
	}
	return newCipher(key, 48)
}

// NewCipher64 creates and returns a new cipher.Block.
// The block size is 64 bits.
// The key argument should be either 96 or 128 bits.
func NewCipher64(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 12, 16:
		break
	}
	return newCipher(key, 64)
}

// NewCipher96 creates and returns a new cipher.Block.
// The block size is 96 bits.
// The key argument should be either 96 or 144 bits.
func NewCipher96(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 12, 18:
		break
	}
	return newCipher(key, 96)
}

// NewCipher128 creates and returns a new cipher.Block.
// The block size is 128 bits.
// The key argument should be either 128, 192, or 256 bits.
func NewCipher128(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16, 24, 32:
		break
	}
	return newCipher(key, 128)
}
