package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func MakeAesCFB(key []byte) *aesCFB {
	return &aesCFB{
		key: key,
	}
}

type aesCFB struct {
	key []byte
}

func (p *aesCFB) Encrypt(sourceData []byte) (data []byte, err error) {
	key := p.key
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes cfb encrypt panic:%+v", e)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data = make([]byte, aes.BlockSize+len(sourceData))
	iv := data[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(data[aes.BlockSize:], sourceData)
	return data, nil
}

func (p *aesCFB) Decrypt(encryptData []byte) (data []byte, err error) {
	key := p.key
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes cfb encrypt panic:%+v", e)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(encryptData) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := encryptData[:aes.BlockSize]
	encryptData = encryptData[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encryptData, encryptData)
	return encryptData, nil
}
