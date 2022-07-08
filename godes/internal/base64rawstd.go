package internal

import "encoding/base64"

func MakeBase64RawStd() *base64RawStd {
	return &base64RawStd{}
}

type base64RawStd struct {
}

func (p *base64RawStd) Encrypt(sourceData []byte) (data string, err error) {
	data = base64.RawStdEncoding.EncodeToString(sourceData)
	return data, nil
}

func (p *base64RawStd) Decrypt(encryptData []byte) (data string, err error) {
	decode, err := base64.RawStdEncoding.DecodeString(string(encryptData))
	if err != nil {
		return "", err
	}
	return string(decode), nil
}
