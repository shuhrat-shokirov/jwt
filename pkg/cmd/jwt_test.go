package main

import (
	"testing"
	"time"
)

func TestDecodeBadToken(t *testing.T) {
	qqq := struct{
		Exp int64 `json:"exp"`
	}{
		Exp: time.Now().Add(time.Hour).Unix(),
	}
	err := Decode("xxx.xxx.xxx.xxx", &qqq)
	if err == nil {
		t.Errorf("Decode() error %v", err)
	}
	err = Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODQwNDI0NzB9.In1vJz3MOArHS41Z9Wzd7BWMTrTjQsFZkYB7OtV6lPw", &qqq)
	if err != nil {
		t.Errorf("Decode() error %v", err)
	}

}
func TestDecodeCanNotDecode(t *testing.T) {
	qqq := struct{
		Exp int64 `json:"exp"`

	}{
		Exp: time.Now().Add(time.Hour).Unix(),
	}
	err := Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.8985465.BcumALTIODycz_uESHilA5xGbUmEst3T6RAHUCAwcIc", &qqq)
	if err == nil {
		t.Errorf("Decode() error %v", err)
	}
	err = Decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODQwNDI0NzB9.In1vJz3MOArHS41Z9Wzd7BWMTrTjQsFZkYB7OtV6lPw", &qqq)
	if err != nil {
		t.Errorf("Decode() error %v", err)
	}
}