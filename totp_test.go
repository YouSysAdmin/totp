package totp

import (
	"fmt"
	"regexp"
	"testing"
)

// RFC 6238 SHA-1 vectors (8-digit OTPs):
// T=59          -> 94287082
// T=1111111109  -> 07081804
// T=1111111111  -> 14050471
// T=1234567890  -> 89005924
// T=2000000000  -> 69279037
// T=20000000000 -> 65353130
//
// Base32 secret for "12345678901234567890":
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

type vector struct {
	timestamp int64
	want6     uint32
}

func Test_generateTOTP_RFC6238_SHA1_Last6(t *testing.T) {
	vectors := []vector{
		{timestamp: 59, want6: 287082},          // 94287082 -> 287082
		{timestamp: 1111111109, want6: 81804},   // 07081804 -> 081804 -> 81804
		{timestamp: 1111111111, want6: 50471},   // 14050471 -> 050471 -> 50471
		{timestamp: 1234567890, want6: 5924},    // 89005924 -> 005924 -> 5924
		{timestamp: 2000000000, want6: 279037},  // 69279037 -> 279037
		{timestamp: 20000000000, want6: 353130}, // 65353130 -> 353130
	}

	for _, tc := range vectors {
		got, err := generateTOTP(rfc6238Secret, tc.timestamp)
		if err != nil {
			t.Fatalf("timestamp=%d: unexpected error: %v", tc.timestamp, err)
		}
		if got != tc.want6 {
			t.Fatalf("timestamp=%d: got %d, want %d", tc.timestamp, got, tc.want6)
		}
	}
}

func Test_generateTOTP_InvalidSecret(t *testing.T) {
	// Not valid base32
	_, err := generateTOTP("not*base32==", 59)
	if err == nil {
		t.Fatal("expected error for invalid base32 secret, got nil")
	}
}

func Test_GetToken_SaneShape(t *testing.T) {
	// We can’t control time.Now() here without changing the API,
	// so we just assert shape: 6 digits.
	secret := rfc6238Secret
	code, err := GetToken(secret)
	if err != nil {
		t.Fatalf("GetToken returned error: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("GetToken length=%d, want 6; value=%q", len(code), code)
	}
	m := regexp.MustCompile(`^\d{6}$`)
	if !m.MatchString(code) {
		t.Fatalf("GetToken produced non-digit characters: %q", code)
	}
}

func Test_Padding(t *testing.T) {
	code, err := generateTOTP(rfc6238Secret, 1111111109) // 07081804 -> 081804 -> numeric 81804
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nonPadded := fmt.Sprintf("%d", code) // "81804"
	padded := fmt.Sprintf("%06d", code)  // "081804"

	if nonPadded == padded {
		t.Fatal("expected non-padded and padded strings to differ")
	}
	if padded != "081804" {
		t.Fatalf("padded output mismatch: got %q, want %q", padded, "081804")
	}
}
