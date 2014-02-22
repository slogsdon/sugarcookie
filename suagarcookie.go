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

func NewSignature(uniqueUserId string) string {
	time := time.Now().Unix()

	hash := sha256.Sum256([]byte(SECRET + strconv.FormatInt(time, 10) + uniqueUserId))
	value := hex.EncodeToString(hash[:]) + "-" + strconv.FormatInt(time, 10) + "-" + uniqueUserId
	signature := base64.StdEncoding.EncodeToString([]byte(value))

	return signature
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
