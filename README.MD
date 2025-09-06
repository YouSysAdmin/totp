# TOTP

Tiny Go helper for generating 6-digit TOTP codes (RFC 6238, HMAC-SHA1).

## Features

- 6-digit codes with proper zero-padding at the call site.
- Base32 secret decoding with error handling.
- Deterministic, timestamp-based generator suitable for tests/examples.

## Install

```bash
go get github.com/yousysadmin/totp
```

## Usage

```go
package main

import (
  "fmt"
  "log"

  "github.com/yousysadmin/totp"
)

func main() {
  // Base32 secret
  secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

  code, err := totp.GetToken(secret)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("TOTP:", code) // TOTP Code 6 digits
}
````
