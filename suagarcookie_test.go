// Copyright 2014 Ukiah Smith. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sugarcookie

import (
	"testing"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func TestNewSignature(t *testing.T) {
    // 世界
}

func TestVerifySignature(t *testing.T) {
	knownSecret := "change-this-secret-key"
	knownTime := "0000000000"
	knownUser := "supermighty"
	knownContent := knownSecret + knownTime + knownUser
	knownHexHash := "53a388232371b201261efb7e3cc141d36dc2b66b0d9da5bd4496bd4f4e0c52ed"
	knownValue := knownHexHash + "-" + knownTime + "-" + knownUser
	knownSignature := "NTNhMzg4MjMyMzcxYjIwMTI2MWVmYjdlM2NjMTQxZDM2ZGMyYjY2YjBkOWRhNWJkNDQ5NmJkNGY0ZTBjNTJlZC0wMDAwMDAwMDAwLXN1cGVybWlnaHR5"

	hash := sha256.Sum256([]byte(knownContent))
	hexHash := hex.EncodeToString(hash[:])
	if hexHash != knownHexHash {
		t.Error("hex representation of secret hash mismatch.")
	}

	testSignature := base64.StdEncoding.EncodeToString([]byte(knownValue))
	if testSignature != knownSignature {
		t.Error("signagure mismatch.")
	}

	v := VerifySignature(knownSignature)
	if v != true {
		t.Error("VerifySignature() failed.")
	}
}
