package builder_test

import (
	"testing"

	"midnight_loader/internal/builder"
)

func TestGenerateKeyLength(t *testing.T) {
	key := builder.GenerateKey()
	if len(key) < 12 || len(key) > 16 {
		t.Fatalf("key length %d out of range [12,16]", len(key))
	}
}

func TestGenerateKeyAlphanumeric(t *testing.T) {
	for i := 0; i < 20; i++ {
		key := builder.GenerateKey()
		for _, c := range key {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				t.Fatalf("non-alphanumeric char %q in key %q", c, key)
			}
		}
	}
}

func TestXOREncryptRoundtrip(t *testing.T) {
	key := "testkey123"
	data := []byte("hello world shellcode")
	enc := builder.XOREncrypt(data, key)
	dec := builder.XOREncrypt(enc, key)
	if string(dec) != string(data) {
		t.Fatalf("roundtrip failed: got %q want %q", dec, data)
	}
}

func TestXOREncryptDeterministic(t *testing.T) {
	key := "abc"
	data := []byte{0x00, 0x01, 0x02}
	enc := builder.XOREncrypt(data, key)
	// 0x00 ^ 'a'=0x61, 0x01 ^ 'b'=0x63, 0x02 ^ 'c'=0x61
	if enc[0] != 0x61 || enc[1] != 0x63 || enc[2] != 0x61 {
		t.Fatalf("unexpected xor output: %v", enc)
	}
}
