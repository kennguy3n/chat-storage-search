// generate_vectors prints canonical Pattern C interop test vectors.
//
// Run with `go run .` from this directory; the output is JSON on
// stdout. The Rust test at
// crates/core/tests/pattern_c_interop_vectors.rs hardcodes the
// values produced by this program — regenerate by piping into that
// file's `VECTORS` block when the upstream Go SDK changes.
//
// The Go SDK is referenced via a local replace directive so this
// program does not require network access at run time.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"github.com/kennguy3n/zk-object-fabric/encryption/client_sdk"
	"lukechampine.com/blake3"
)

type Vector struct {
	Name        string `json:"name"`
	ContentHash string `json:"content_hash_hex"`
	TenantID    string `json:"tenant_id"`
	Plaintext   string `json:"plaintext_hex"`
	ChunkSize   int    `json:"chunk_size"`
	DEK         string `json:"dek_hex"`
	Nonce0      string `json:"nonce0_hex"`
	Ciphertext  string `json:"ciphertext_hex"`
}

// firstChunkNonce derives the convergent nonce for chunk_index = 0
// via the public Go SDK path: encrypt one byte with ConvergentNonce
// = true and read the first 24 bytes off the wire. This is exactly
// what TestEncryptObject_ConvergentNonce_MatchesDeriveHelper in the
// Go SDK validates, so it is the canonical "first chunk nonce".
func firstChunkNonce(dek client_sdk.DataEncryptionKey, chunkSize int) ([]byte, error) {
	enc, err := client_sdk.EncryptObject(bytes.NewReader([]byte{0}), dek, client_sdk.Options{
		ChunkSize:       chunkSize,
		ConvergentNonce: true,
	})
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(enc)
	if err != nil {
		return nil, err
	}
	if len(out) < 24 {
		return nil, fmt.Errorf("ciphertext shorter than nonce: %d", len(out))
	}
	return out[:24], nil
}

func encrypt(plain []byte, dek client_sdk.DataEncryptionKey, chunkSize int) ([]byte, error) {
	enc, err := client_sdk.EncryptObject(bytes.NewReader(plain), dek, client_sdk.Options{
		ChunkSize:       chunkSize,
		ConvergentNonce: true,
	})
	if err != nil {
		return nil, err
	}
	return io.ReadAll(enc)
}

func main() {
	type input struct {
		Name      string
		Tenant    string
		Plaintext []byte
		Chunk     int
	}

	inputs := []input{
		{"hello-world", "test-tenant-001", []byte("hello world"), 64},
		{"single-x", "tnt", []byte("x"), 16},
		{"abcd-1024-multi-chunk", "tnt_a", bytes.Repeat([]byte("abcd"), 1024), 256},
		{"128-bytes-of-AB", "multi-chunk-tenant", bytes.Repeat([]byte{0xAB}, 128), 64},
	}

	out := make([]Vector, 0, len(inputs))
	for _, in := range inputs {
		h := blake3.Sum256(in.Plaintext)
		dek, err := client_sdk.DeriveConvergentDEK(h[:], in.Tenant)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DeriveConvergentDEK(%s): %v\n", in.Name, err)
			os.Exit(1)
		}
		nonce0, err := firstChunkNonce(dek, in.Chunk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "firstChunkNonce(%s): %v\n", in.Name, err)
			os.Exit(1)
		}
		ct, err := encrypt(in.Plaintext, dek, in.Chunk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "encrypt(%s): %v\n", in.Name, err)
			os.Exit(1)
		}
		out = append(out, Vector{
			Name:        in.Name,
			ContentHash: hex.EncodeToString(h[:]),
			TenantID:    in.Tenant,
			Plaintext:   hex.EncodeToString(in.Plaintext),
			ChunkSize:   in.Chunk,
			DEK:         hex.EncodeToString([]byte(dek)),
			Nonce0:      hex.EncodeToString(nonce0),
			Ciphertext:  hex.EncodeToString(ct),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
}
