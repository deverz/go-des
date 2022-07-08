package internal

import "encoding/base64"

func MakeBase64RawUrl() *base64RawUrl {
	return &base64RawUrl{}
}

type base64RawUrl struct {
}

func (p *base64RawUrl) Encrypt(sourceData []byte) (data string, err error) {
	data = base64.RawURLEncoding.EncodeToString(sourceData)
	return data, nil
}

func (p *base64RawUrl) Decrypt(encryptData []byte) (data string, err error) {
	decode, err := base64.RawURLEncoding.DecodeString(string(encryptData))
	if err != nil {
		return "", err
	}
	return string(decode), nil
}
