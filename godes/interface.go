package godes

// IDESInterface  接口
type IDESInterface interface {
	Encrypt(sourceData []byte) (data string, err error)  // 加密
	Decrypt(encryptData []byte) (data string, err error) // 解密
}
