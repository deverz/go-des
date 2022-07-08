package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// aes:https://go.dev/src/crypto/cipher/example_test.go

func MakeAesCBC7(key []byte) *aesCBC7 {
	return &aesCBC7{
		key: key,
	}
}

type aesCBC7 struct {
	key []byte // 秘钥
}

// Encrypt aes cbc 加密
// sourceData 要加密的数据
// key 秘钥：16位 24位 32位 对应：aes-128 aes-192 aes-256
// NewCipher该函数限制了输入k的长度必须为16, 24或者32
func (p *aesCBC7) Encrypt(sourceData []byte) (str string, err error) {
	key := p.key
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes cbc7 encrypt panic:%+v", e)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// 进行PKCS7填充
	blockSize := block.BlockSize() //16位
	sourceData = toPKCS7Padding(sourceData, blockSize)

	data := make([]byte, blockSize+len(sourceData))
	//block大小 16
	iv := data[:blockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	// 加密
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(data[blockSize:], sourceData)
	return string(data), nil
}

func (p *aesCBC7) Decrypt(encryptData []byte) (str string, err error) {
	key := p.key
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes cbc7 decrypt panic:%+v", e)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize() //16位
	if len(encryptData) < blockSize {
		return "", errors.New("cbc7 encryptData too short")
	}
	// 解iv
	iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]
	if len(encryptData)%blockSize != 0 {
		return "", errors.New("cbc7 encryptData is invalid")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptData, encryptData)
	encryptData = unPKCS7Padding(encryptData)
	return string(encryptData), nil
}

// toPKCS7Padding PKCS7 填充
func toPKCS7Padding(sourceData []byte, blockSize int) []byte {
	// 计算离一个块大小差多少 16字节
	paddingNum := blockSize - len(sourceData)%blockSize
	// 根据计算差值，生成一个差值大小的字节切片 16字节
	paddingText := bytes.Repeat([]byte{byte(paddingNum)}, paddingNum)
	return append(sourceData, paddingText...)
}

// unPKCS7Padding PKCS7 解填充
func unPKCS7Padding(encryptData []byte) []byte {
	length := len(encryptData)
	unPadding := int(encryptData[length-1])
	return encryptData[:(length - unPadding)]
}
