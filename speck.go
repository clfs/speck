// Package speck implements the Speck cipher.
package speck

import (
	"crypto/cipher"
	"fmt"
)

type SizeError struct {
	BlockSize int
	KeySize   int
}

func (e SizeError) Error() string {
	return fmt.Sprintf("speck: invalid block size %d and key size %d", e.BlockSize, e.KeySize)
}

type speckCipher struct {
	key       []byte
	blockSize int
	rounds    int
}

func (s speckCipher) BlockSize() int {
	return s.blockSize
}

func (s speckCipher) Encrypt(dst, src []byte) {

}

func (s speckCipher) Decrypt(dst, src []byte) {

}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte, blockSize int) (cipher.Block, error) {
	var rounds int
	keySize := len(key)
	switch {
	default:
		return nil, SizeError{blockSize, keySize}
	case blockSize == 4 && keySize == 8:
		rounds = 22
	case blockSize == 6 && keySize == 9:
		rounds = 22
	case blockSize == 6 && keySize == 12:
		rounds = 23
	case blockSize == 8 && keySize == 12:
		rounds = 26
	case blockSize == 8 && keySize == 16:
		rounds = 27
	case blockSize == 12 && keySize == 12:
		rounds = 28
	case blockSize == 12 && keySize == 18:
		rounds = 29
	case blockSize == 16 && keySize == 16:
		rounds = 32
	case blockSize == 16 && keySize == 24:
		rounds = 33
	case blockSize == 16 && keySize == 32:
		rounds = 34
	}
	return speckCipher{blockSize: blockSize, key: key, rounds: rounds}, nil
}
