package godes

import "github.com/deverz/go-des/godes/internal"

func MakeDES(t DesType, key ...[]byte) IDESInterface {
	switch t {
	case AesCBC7:
		if len(key) == 0 {
			return nil
		}
		return internal.MakeAesCBC7(key[0])
	case AesCBC5:
		if len(key) == 0 {
			return nil
		}
		return internal.MakeAesCBC5(key[0])
	case AesECB:
		if len(key) == 0 {
			return nil
		}
		return internal.MakeAesECB(key[0])
	case Base64Std:
		return internal.MakeBase64Std()
	case Base64URL:
		return internal.MakeBase64Url()
	case Base64RawStd:
		return internal.MakeBase64RawStd()
	case Base64RawURL:
		return internal.MakeBase64RawUrl()
	case MD5:
		return internal.MakeMd5()
	}
	return nil
}
