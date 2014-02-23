// Copyright 2014 Ukiah Smith. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sugarcookie

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	SECRET = "change-this-secret-key"
)

func newSignature(secret string, t int64, uniqueUserId string) string {
	hash := sha256.Sum256([]byte(secret + strconv.FormatInt(t, 10) + uniqueUserId))
	value := hex.EncodeToString(hash[:]) + "-" + strconv.FormatInt(t, 10) + "-" + uniqueUserId
	fmt.Println( strconv.FormatInt(t, 10) )
	signature := base64.StdEncoding.EncodeToString([]byte(value))

	return signature
}

func NewSignature(uniqueUserId string) string {
	t := time.Now().Unix()
	return newSignature(SECRET, t, uniqueUserId)
}

func VerifySignature(signature string) bool {
	unpack, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println("error: ", err)
		return false
	}

	values := strings.Split(string(unpack[:]), "-")
	testHash := sha256.Sum256([]byte(SECRET + values[1] + values[2]))
	if hex.EncodeToString(testHash[:]) == values[0] {
		return true
	} else {
		return false
	}
}
