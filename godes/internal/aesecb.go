package internal

import (
	"crypto/aes"
	"fmt"
)

func MakeAesECB(key []byte) *aesECB {
	return &aesECB{
		key: key,
	}
}

type aesECB struct {
	key []byte
}

// Encrypt aes ecb 加密
// sourceData 要加密的数据
// key 秘钥
func (p *aesECB) Encrypt(sourceData []byte) (str string, err error) {
	key := p.key
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes ecb encrypt panic:%+v", e)
		}
	}()
	cipher, err := aes.NewCipher(formatKey(key))
	if err != nil {
		return "", err
	}
	length := (len(sourceData) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, sourceData)
	pad := byte(len(plain) - len(sourceData))
	for i := len(sourceData); i < len(plain); i++ {
		plain[i] = pad
	}
	data := make([]byte, len(plain))
	// 分组分块加密
	for bs, be := 0, cipher.BlockSize(); bs <= len(sourceData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(data[bs:be], plain[bs:be])
	}

	return string(data), nil
}

// Decrypt aes ecb 解密
func (p *aesECB) Decrypt(encryptData []byte) (str string, err error) {
	key := p.key
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes ecb decrypt panic:%+v", e)
		}
	}()
	cipher, err := aes.NewCipher(formatKey(key))
	if err != nil {
		return "", err
	}
	data := make([]byte, len(encryptData))
	for bs, be := 0, cipher.BlockSize(); bs < len(encryptData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(data[bs:be], encryptData[bs:be])
	}

	trim := 0
	if len(data) > 0 {
		trim = len(data) - int(data[len(data)-1])
	}

	return string(data[:trim]), nil
}

func formatKey(key []byte) (nKey []byte) {
	nKey = make([]byte, 16)
	copy(nKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			nKey[j] ^= key[i]
		}
	}
	return nKey
}
