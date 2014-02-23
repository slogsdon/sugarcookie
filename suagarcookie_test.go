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
	knownSecret := "change-this-secret-key"
	knownTime := int64(0)
	knownUser := "supermighty"
	knownSignature := "OGRmYjNmZjFlZmRlODI0NWY1N2JlN2JhNWFmNGVhZGNiYmNkYWU3NjcyOGExODFjMGVjNjNiNjQ1N2FiM2UzYy0wLXN1cGVybWlnaHR5"

	testSignature := newSignature(knownSecret, knownTime, knownUser)
	if testSignature != knownSignature {
		t.Error("newSignagure() Signature mismatch.")
	}
}

func TestVerifySignature(t *testing.T) {
	knownSecret := "change-this-secret-key"
	knownTime := "0"
	knownUser := "supermighty"
	knownContent := knownSecret + knownTime + knownUser
	knownHexHash := "8dfb3ff1efde8245f57be7ba5af4eadcbbcdae76728a181c0ec63b6457ab3e3c"
	knownValue := knownHexHash + "-" + knownTime + "-" + knownUser
	knownSignature := "OGRmYjNmZjFlZmRlODI0NWY1N2JlN2JhNWFmNGVhZGNiYmNkYWU3NjcyOGExODFjMGVjNjNiNjQ1N2FiM2UzYy0wLXN1cGVybWlnaHR5"

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
