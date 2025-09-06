package totp

import (
	"encoding/base32"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"
)

const benchSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // RFC6238 b32("12345678901234567890")

// Benchmark the core generator at a fixed timestamp.
func Benchmark_generateTOTP_Fixed(b *testing.B) {
	b.ReportAllocs()
	ts := int64(1234567890)
	for b.Loop() {
		if _, err := generateTOTP(benchSecret, ts); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark the generator across many different timestamps within a typical window range.
func Benchmark_generateTOTP_VaryingTimestamps(b *testing.B) {
	b.ReportAllocs()
	start := time.Now().UTC().Unix()
	for i := 0; b.Loop(); i++ {
		// Walk forward by i seconds to vary the counter; keeps things deterministic.
		ts := start + int64(i%3000) // ~50 minutes span
		if _, err := generateTOTP(benchSecret, ts); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark GetToken (includes time.Now + zero-padding) to reflect public API overhead.
func Benchmark_GetToken(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := GetToken(benchSecret); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark in parallel to simulate many goroutines generating codes concurrently.
func Benchmark_generateTOTP_Parallel(b *testing.B) {
	b.ReportAllocs()
	var ctr uint64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// spread timestamps across goroutines deterministically
			ts := int64(59 + atomic.AddUint64(&ctr, 1)%100000)
			if _, err := generateTOTP(benchSecret, ts); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Benchmark Base32 decode alone to gauge how much cost comes from decoding.
func Benchmark_base32Decode(b *testing.B) {
	b.ReportAllocs()
	dec := base32.StdEncoding.WithPadding(base32.NoPadding)
	for b.Loop() {
		if _, err := dec.DecodeString(benchSecret); err != nil {
			b.Fatal(err)
		}
	}
}

// Sweep consecutive 30s windows; useful if you want to compare with/without caching anything externally.
func Benchmark_generateTOTP_WindowSweep(b *testing.B) {
	b.ReportAllocs()
	// Pick an arbitrary aligned start.
	start := time.Now().UTC().Unix() - (time.Now().UTC().Unix() % 30)
	for i := 0; b.Loop(); i++ {
		ts := start + int64((i%2000)*30) // 2000 windows
		if _, err := generateTOTP(benchSecret, ts); err != nil {
			b.Fatal(err)
		}
	}
}

// Random timestamps, stable seed for reproducibility.
func Benchmark_generateTOTP_RandomTimestamps(b *testing.B) {
	b.ReportAllocs()
	r := rand.New(rand.NewSource(42))
	now := time.Now().UTC().Unix()
	for b.Loop() {
		jitter := r.Int63n(86400) // +/- one day
		sign := int64(1)
		if r.Intn(2) == 0 {
			sign = -1
		}
		ts := now + sign*jitter
		if _, err := generateTOTP(benchSecret, ts); err != nil {
			b.Fatal(err)
		}
	}
}

// Micro: measure string formatting cost from the caller perspective.
func Benchmark_zeroPadFormatting(b *testing.B) {
	b.ReportAllocs()
	ts := int64(1111111109) // produces a code with leading zero in RFC vector
	code, err := generateTOTP(benchSecret, ts)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		_ = fmt.Sprintf("%06d", code)
	}
}
