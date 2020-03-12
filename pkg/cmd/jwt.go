package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"time"
)

const (
	jsonKey = "json"
	expTag  = "exp"
)

func main() {
	qqq := struct{
		Exp int64 `json:"exp"`

	}{
		Exp: time.Now().Add(time.Hour).Unix(),
	}
	x, _ := Encode(qqq, []byte("top"))
	log.Printf("this token: %s", x)
	log.Print(x)
	var decode interface{}
	decode = qqq
	_ = Decode(x, &decode)
	log.Printf("token after decode : %s", decode)
	it := justDoIt(qqq)
	log.Print(it)
	x, _ = Encode(qqq, []byte("top"))
	verify, err := Verify(x, []byte("top"))
	log.Print(verify)
	log.Print(err)

}

func Decode(token string, payload interface{}) (err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("bad token")
	}

	payloadEncoded := parts[1]
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return errors.New("can't decode")
	}
	err = json.Unmarshal(payloadJSON, payload)
	if err != nil {
		log.Print(err)
		return errors.New("can't decode")
	}

	return
}

func Verify(token string, secret []byte) (bool, error) {
	split := strings.Split(token, ".")

	h := hmac.New(sha256.New, secret)
	_, err := h.Write([]byte(fmt.Sprintf("%s.%s", split[0], split[1])))
	if err != nil {
		log.Print(err)
		return false, err
	}
	signature := h.Sum(nil)
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)
	if signatureEncoded != split[2] {
		return false, errors.New("invalid token")
	}
	payload := struct{
		Exp int64 `json:"exp"`
	}{
		Exp: -99,
	}
	err = Decode(token, &payload)
	if err != nil {
		log.Print(err)
		return false, err
	}
	if payload.Exp == -99{
		return false, errors.New("field exp not found")
	}
	it := justDoIt(payload)
	if it == -1{
		return false, errors.New("some errors in justDoIt")
	}
	fmt.Println(time.Now().Unix(), it)
	if time.Now().Unix() > it {
		return false, errors.New("Out of date exploitation ")
	}
	return true, nil
}

func justDoIt(payload interface{}) int64 {
	reflectType := reflect.TypeOf(payload)
	reflectValue := reflect.ValueOf(payload)
	if reflectType.Kind() == reflect.Ptr {
		reflectType = reflectType.Elem()
		reflectValue = reflectValue.Elem()
	}

	if reflectType.Kind() != reflect.Struct {
		panic(errors.New("give me struct or pointer to it"))
	}

	fieldCount := reflectType.NumField()
	for i := 0; i < fieldCount; i++ {
		field := reflectType.Field(i)
		tag, ok := field.Tag.Lookup(jsonKey)
		if !ok {
			continue
		}
		if tag == expTag {
			value := reflectValue.Field(i)
			if value.Kind() != reflect.Int64 {
				log.Print(errors.New("exp should be int64"))
				return -1
			}
			exp := value.Interface().(int64)
			return exp
		}
	}
	return -1
}

func Encode(payload interface{}, secret []byte) (token string, err error) {
	header := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{
		Alg: "HS256",
		Typ: "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	h := hmac.New(sha256.New, secret)
	h.Write([]byte(headerEncoded + "." + payloadEncoded))
	signature := h.Sum(nil)

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)
	token = fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signatureEncoded)
	return
}
