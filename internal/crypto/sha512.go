package crypto

import "crypto/sha512"

func sha512Sum(b []byte) [64]byte { return sha512.Sum512(b) }
