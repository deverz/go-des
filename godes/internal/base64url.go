package internal

import "encoding/base64"

func MakeBase64Url() *base64Url {
	return &base64Url{}
}

type base64Url struct {
}

func (p *base64Url) Encrypt(sourceData []byte) (data string, err error) {
	data = base64.URLEncoding.EncodeToString(sourceData)
	return data, nil
}

func (p *base64Url) Decrypt(encryptData []byte) (data string, err error) {
	decode, err := base64.URLEncoding.DecodeString(string(encryptData))
	if err != nil {
		return "", err
	}
	return string(decode), nil
}
