package internal

import "encoding/base64"

func MakeBase64Std() *base64Std {
	return &base64Std{}
}

type base64Std struct {
}

func (p *base64Std) Encrypt(sourceData []byte) (data string, err error) {
	data = base64.StdEncoding.EncodeToString(sourceData)
	return data, nil
}

func (p *base64Std) Decrypt(encryptData []byte) (data string, err error) {
	decode, err := base64.StdEncoding.DecodeString(string(encryptData))
	if err != nil {
		return "", err
	}
	return string(decode), nil
}
