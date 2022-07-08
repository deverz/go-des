package internal

import (
	"crypto/md5"
	"encoding/hex"
)

func MakeMd5() *md5n {
	return &md5n{}
}

type md5n struct {
}

// Encrypt md5加密
func (p *md5n) Encrypt(sourceData []byte) (data string, err error) {
	h := md5.New()
	h.Write(sourceData)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Decrypt md5无解密
func (p *md5n) Decrypt(encryptData []byte) (data string, err error) {
	return string(encryptData), nil
}
