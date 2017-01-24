package main

import "testing"
import "encoding/hex"
import "reflect"

func TestEncrpt(t *testing.T) {
	data := Encrpt([]byte("Test"))
	hex := hex.EncodeToString(data)
	if hex != "e4a41814fffca7c6" {
		t.Fail()
	}
}

func TestDecrpt(t *testing.T) {
	src, _ := hex.DecodeString("e4a41814fffca7c6")
	data := Decrpt(src)
	if !reflect.DeepEqual(data, []byte("test")) {
		t.Fail()
	}
}
