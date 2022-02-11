package goaes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

/*
 * @Desc: aes:https://go.dev/src/crypto/cipher/example_test.go
 * @Author: deverz@qq.com
 * @File: goaes/aes.go
 * @Date: 2022/2/10 11:41 上午
 */

// toPKCS7Padding PKCS7填充
func toPKCS7Padding(sourceData []byte, blockSize int) []byte {
	// 计算离一个块大小差多少 16字节
	paddingNum := blockSize - len(sourceData)%blockSize
	// 根据计算差值，生成一个差值大小的字节切片 16字节
	paddingText := bytes.Repeat([]byte{byte(paddingNum)}, paddingNum)
	return append(sourceData, paddingText...)
}

// unPKCS7Padding PKCS7解填充
func unPKCS7Padding(encryptData []byte) []byte {
	length := len(encryptData)
	unPadding := int(encryptData[length-1])
	return encryptData[:(length - unPadding)]
}

// AesCBCEncrypt aes cbc 加密
// sourceData 要加密的数据
// key 秘钥：16位 24位 32位 对应：aes-128 aes-192 aes-256
func AesCBCEncrypt(sourceData, key []byte) (data []byte, err error) {
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes encrypt panic:%+v", e)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 进行PKCS7填充
	blockSize := block.BlockSize() //16位
	sourceData = toPKCS7Padding(sourceData, blockSize)

	cipherText := make([]byte, blockSize+len(sourceData))
	//block大小 16
	iv := cipherText[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	// 加密
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], sourceData)
	return cipherText, nil
}

// AesCBCDecrypt aes cbc 解密
func AesCBCDecrypt(encryptData, key []byte) (data []byte, err error) {
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes decrypt panic:%+v", e)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize() //16位
	if len(encryptData) < blockSize {
		return nil, errors.New("encryptData too short")
	}
	// 解iv
	iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]
	if len(encryptData)%blockSize != 0 {
		return nil, errors.New("encryptData is invalid")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptData, encryptData)
	encryptData = unPKCS7Padding(encryptData)
	return encryptData, nil
}

// EnAesBase64 aes加密后转义为base64可直接用作url参数
func EnAesBase64(sourceData, key string) ([]byte, error) {
	if len(sourceData)|len(key) == 0 {
		return nil, errors.New("params is invalid")
	}
	data, err := AesCBCEncrypt([]byte(sourceData), []byte(key))
	if err != nil {
		return nil, err
	}
	encryptData := base64.RawURLEncoding.EncodeToString(data)
	return []byte(encryptData), nil
}

// DeAesBase64 解密
func DeAesBase64(encryptString, key string) ([]byte, error) {
	if len(encryptString)|len(key) == 0 {
		return nil, errors.New("params is invalid")
	}
	base, err := base64.RawURLEncoding.DecodeString(encryptString)
	if err != nil {
		return nil, err
	}
	decryptData, err := AesCBCDecrypt(base, []byte(key))
	if err != nil {
		return nil, err
	}
	return decryptData, nil
}
