# TOTP

[![Go CI](https://github.com/YouSysAdmin/totp/actions/workflows/go.yml/badge.svg)](https://github.com/YouSysAdmin/totp/actions/workflows/go.yml)

Tiny Go helper for generating 6-digit TOTP codes (RFC 6238, HMAC-SHA1).

## Features

- Generate 6-digit TOTP code from MFA secret

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
