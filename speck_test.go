package speck_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	. "github.com/clfs/speck"
	"github.com/clfs/speck/internal/ecb"
)

func convert(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

var testVectors = map[string]struct {
	blockSize   int
	key, pt, ct string
}{
	"Speck32/64": {
		blockSize: 4,
		key:       "1918 1110 0908 0100",
		pt:        "6574 694c",
		ct:        "a868 42f2",
	},
	"Speck48/72": {
		blockSize: 6,
		key:       "121110 0a0908 020100",
		pt:        "20796c 6c6172",
		ct:        "c049a5 385adc",
	},
	"Speck48/96": {
		blockSize: 6,
		key:       "1a1918 121110 0a0908 020100",
		pt:        "6d2073 696874",
		ct:        "735e10 b6445d",
	},
	"Speck64/96": {
		blockSize: 8,
		key:       "13121110 0b0a0908 03020100",
		pt:        "74614620 736e6165",
		ct:        "9f7952ec 4175946c",
	},
	"Speck64/128": {
		blockSize: 8,
		key:       "1b1a1918 13121110 0b0a0908 03020100",
		pt:        "3b726574 7475432d",
		ct:        "8c6fa548 454e028b",
	},
	"Speck96/96": {
		blockSize: 12,
		key:       "0d0c0b0a0908 050403020100",
		pt:        "65776f68202c 656761737520",
		ct:        "9e4d09ab7178 62bdde8f79aa",
	},
	"Speck96/144": {
		blockSize: 12,
		key:       "151413121110 0d0c0b0a0908 050403020100",
		pt:        "656d6974206e 69202c726576",
		ct:        "2bf31072228a 7ae440252ee6",
	},
	"Speck128/128": {
		blockSize: 16,
		key:       "0f0e0d0c0b0a0908 0706050403020100",
		pt:        "6c61766975716520 7469206564616d20",
		ct:        "a65d985179783265 7860fedf5c570d18",
	},
	"Speck128/192": {
		blockSize: 16,
		key:       "1716151413121110 0f0e0d0c0b0a0908 0706050403020100",
		pt:        "7261482066656968 43206f7420746e65",
		ct:        "1be4cf3a13135566 f9bc185de03c1886",
	},
	"Speck128/256": {
		blockSize: 16,
		key:       "1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100",
		pt:        "65736f6874206e49 202e72656e6f6f70",
		ct:        "4109010405c0f53e 4eeeb48d9c188f43",
	},
}

func TestEncryptTestVectors(t *testing.T) {
	t.Parallel()
	for name, tc := range testVectors {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var (
				key = convert(t, tc.key)
				pt  = convert(t, tc.pt)
				ct  = convert(t, tc.ct)
			)
			cipher, err := NewCipher(key, tc.blockSize)
			if err != nil {
				t.Fatal(err)
			}
			encrypter := ecb.NewEncrypter(cipher)
			encrypter.CryptBlocks(pt, pt)
			if !bytes.Equal(ct, pt) {
				t.Errorf("expected %x, got %x", ct, pt)
			}
		})
	}
}

func TestDecryptTestVectors(t *testing.T) {
	t.Parallel()
	for name, tc := range testVectors {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var (
				key = convert(t, tc.key)
				pt  = convert(t, tc.pt)
				ct  = convert(t, tc.ct)
			)
			cipher, err := NewCipher(key, tc.blockSize)
			if err != nil {
				t.Fatal(err)
			}
			decrypter := ecb.NewDecrypter(cipher)
			decrypter.CryptBlocks(ct, ct)
			if !bytes.Equal(pt, ct) {
				t.Errorf("expected %x, got %x", pt, ct)
			}
		})
	}
}
