package internal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func MakeAesCBC5(key []byte) *aesCBC5 {
	return &aesCBC5{
		key: key,
	}
}

type aesCBC5 struct {
	key []byte // 秘钥
}

func (p *aesCBC5) Encrypt(sourceData []byte) (str string, err error) {
	key := p.key
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes cbc5 encrypt panic:%+v", e)
		}
	}()
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()                              // 获取秘钥块的长度
	sourceData = toPKCS5Padding(sourceData, blockSize)          // 补全码
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) // 加密模式
	data := make([]byte, len(sourceData))                       // 创建数组
	blockMode.CryptBlocks(data, sourceData)                     // 加密
	return string(data), nil
}

func (p *aesCBC5) Decrypt(encryptData []byte) (str string, err error) {
	key := p.key
	// 捕捉panic
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("aes cbc5 encrypt panic:%+v", e)
		}
	}()
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()                              // 获取秘钥块的长度
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) // 加密模式
	data := make([]byte, len(encryptData))                      // 创建数组
	blockMode.CryptBlocks(data, encryptData)                    // 解密
	data = unPKCS5Padding(data)                                 // 去除补全码
	return string(data), nil
}

func toPKCS5Padding(sourceData []byte, blockSize int) []byte {
	paddingNum := blockSize - len(sourceData)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingNum)}, paddingNum)
	return append(sourceData, paddingText...)
}

func unPKCS5Padding(encryptData []byte) []byte {
	length := len(encryptData)
	unPadding := int(encryptData[length-1])
	return encryptData[:(length - unPadding)]
}
