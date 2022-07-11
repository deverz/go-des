package godes

// Base64
// StdEncoding：常规编码
// URLEncoding：URL safe 编码
// RawStdEncoding：常规编码，末尾不补 =
// RawURLEncoding：URL safe 编码，末尾不补 =
// URL safe 编码，相当于是替换掉字符串中的特殊字符，+ 和 /。

type DesType int

const (
	AesCBC7      DesType = iota + 1 // cbc加密 pkcs7填充
	AesCBC5                         // cbc加密 pkcs5填充
	AesECB                          // ecb加密
	Base64Std                       // 常规编码
	Base64URL                       // URL safe 编码
	Base64RawStd                    // 常规编码，末尾不补 =
	Base64RawURL                    // URL safe 编码，末尾不补 =
	MD5
)
