package main

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"log"
)

func Encrpt(src []byte) []byte {
	pass := []byte("igtasd")
	key := make([]byte, 24)
	copy(key, pass)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		log.Fatalln(err.Error())
	}
	iv, _ := hex.DecodeString("f05644ff394667fb")
	mode := cipher.NewCBCEncrypter(block, iv)

	src, err = pkcs7Pad(src, block.BlockSize())
	if err != nil {
		log.Fatalln(err.Error())
	}
	dst := make([]byte, len(src))
	mode.CryptBlocks(dst, src)
	dst, err = pkcs7Unpad(dst, block.BlockSize())
	if err != nil {
		log.Println(err.Error())
	}
	return dst
}

func Decrpt(src []byte) []byte {
	pass := []byte("igtasd")
	key := make([]byte, 24)
	copy(key, pass)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		log.Fatalln(err.Error())
	}
	iv, _ := hex.DecodeString("f05644ff394667fb")
	mode := cipher.NewCBCDecrypter(block, iv)
	dst := make([]byte, len(src))
	mode.CryptBlocks(dst, src)
	return dst
}
