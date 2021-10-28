package speck_test

import (
	"bytes"
	"crypto/cipher"
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

func TestTestVectors(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		f           func([]byte) (cipher.Block, error)
		key, pt, ct []byte
	}{
		"Speck32/64": {
			f:   NewCipher32,
			key: convert(t, "1918 1110 0908 0100"),
			pt:  convert(t, "6574 694c"),
			ct:  convert(t, "a868 42f2"),
		},
		"Speck48/72": {
			f:   NewCipher48,
			key: convert(t, "121110 0a0908 020100"),
			pt:  convert(t, "20796c 6c6172"),
			ct:  convert(t, "c049a5 385adc"),
		},
		"Speck48/96": {
			f:   NewCipher48,
			key: convert(t, "1a1918 121110 0a0908 020100"),
			pt:  convert(t, "6d2073 696874"),
			ct:  convert(t, "735e10 b6445d"),
		},
		"Speck64/96": {
			f:   NewCipher64,
			key: convert(t, "13121110 0b0a0908 03020100"),
			pt:  convert(t, "74614620 736e6165"),
			ct:  convert(t, "9f7952ec 4175946c"),
		},
		"Speck64/128": {
			f:   NewCipher64,
			key: convert(t, "1b1a1918 13121110 0b0a0908 03020100"),
			pt:  convert(t, "3b726574 7475432d"),
			ct:  convert(t, "8c6fa548 454e028b"),
		},
		"Speck96/96": {
			f:   NewCipher96,
			key: convert(t, "0d0c0b0a0908 050403020100"),
			pt:  convert(t, "65776f68202c 656761737520"),
			ct:  convert(t, "9e4d09ab7178 62bdde8f79aa"),
		},
		"Speck96/144": {
			f:   NewCipher96,
			key: convert(t, "151413121110 0d0c0b0a0908 050403020100"),
			pt:  convert(t, "656d6974206e 69202c726576"),
			ct:  convert(t, "2bf31072228a 7ae440252ee6"),
		},
		"Speck128/128": {
			f:   NewCipher128,
			key: convert(t, "0f0e0d0c0b0a0908 0706050403020100"),
			pt:  convert(t, "6c61766975716520 7469206564616d20"),
			ct:  convert(t, "a65d985179783265 7860fedf5c570d18"),
		},
		"Speck128/192": {
			f:   NewCipher128,
			key: convert(t, "1716151413121110 0f0e0d0c0b0a0908 0706050403020100"),
			pt:  convert(t, "7261482066656968 43206f7420746e65"),
			ct:  convert(t, "1be4cf3a13135566 f9bc185de03c1886"),
		},
		"Speck128/256": {
			f:   NewCipher128,
			key: convert(t, "1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100"),
			pt:  convert(t, "65736f6874206e49 202e72656e6f6f70"),
			ct:  convert(t, "4109010405c0f53e 4eeeb48d9c188f43"),
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cipher, err := tc.f(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			encrypter := ecb.NewEncrypter(cipher)
			encrypter.CryptBlocks(tc.pt, tc.pt)
			if !bytes.Equal(tc.pt, tc.ct) {
				t.Errorf("expected %x, got %x", tc.ct, tc.pt)
			}
		})
	}
}
